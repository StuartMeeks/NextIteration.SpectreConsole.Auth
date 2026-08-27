using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Infrastructure
{
    /// <summary>
    /// Tests for the retry helper itself. It stopped being a trivial loop once it began
    /// swallowing exceptions, and a retry helper that quietly swallows a persistent failure
    /// would turn every test that uses it into a test that cannot fail — the exact vacuity
    /// this suite has been cleaning up. These pin the boundary.
    /// </summary>
    public sealed class RetryHelperTests
    {
        [Fact]
        public async Task UntilTrueAsync_RidesOutATransientThrow()
        {
            var attempts = 0;

            var result = await RetryHelper.UntilTrueAsync(() =>
            {
                attempts++;
                return attempts < 3
                    ? throw new InvalidOperationException("SecItemCopyMatching failed: OSStatus -67701.")
                    : Task.FromResult(true);
            }, maxAttempts: 5, delayMs: 1);

            Assert.True(result);
            Assert.Equal(3, attempts);
        }

        [Fact]
        public async Task UntilTrueAsync_RethrowsWhenEveryAttemptThrows()
        {
            var attempts = 0;

            // The load-bearing case: a persistent failure must still fail the test, with its
            // real message, rather than being reported as a benign "false".
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => RetryHelper.UntilTrueAsync(() =>
                {
                    attempts++;
                    throw new InvalidOperationException("persistent");
                }, maxAttempts: 3, delayMs: 1));

            Assert.Equal("persistent", ex.Message);
            Assert.Equal(3, attempts);
        }

        [Fact]
        public async Task UntilAsync_RidesOutATransientThrow()
        {
            var attempts = 0;

            var result = await RetryHelper.UntilAsync(() =>
            {
                attempts++;
                return attempts < 3
                    ? throw new InvalidOperationException("transient")
                    : Task.FromResult(42);
            }, r => r == 42, maxAttempts: 5, delayMs: 1);

            Assert.Equal(42, result);
            Assert.Equal(3, attempts);
        }

        [Fact]
        public async Task UntilAsync_RethrowsWhenEveryAttemptThrows()
        {
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => RetryHelper.UntilAsync<int>(
                    () => throw new InvalidOperationException("persistent"),
                    r => true, maxAttempts: 3, delayMs: 1));

            Assert.Equal("persistent", ex.Message);
        }

        [Fact]
        public async Task UntilAsync_ReturnsTheLastResultWhenThePredicateNeverHolds()
        {
            var attempts = 0;

            // Unchanged behaviour, pinned because the rewrite could easily have lost it:
            // the caller's own assertion must report the real value, not a timeout.
            var result = await RetryHelper.UntilAsync(() =>
            {
                attempts++;
                return Task.FromResult(attempts);
            }, r => false, maxAttempts: 4, delayMs: 1);

            Assert.Equal(4, attempts);
            Assert.Equal(4, result);
        }

        [Fact]
        public async Task UntilTrueAsync_ReturnsFalseWhenTheTargetIsGenuinelyAbsent()
        {
            var result = await RetryHelper.UntilTrueAsync(
                () => Task.FromResult(false), maxAttempts: 3, delayMs: 1);

            Assert.False(result);
        }
    }
}

using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence
{
    public sealed class SelectionsLockTests
    {
        [Fact]
        public async Task Acquire_WhenUncontended_Succeeds()
        {
            using var temp = new TempDir();
            var lockPath = Path.Join(temp.Path, "selections.json.lock");

            using var held = await SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken);

            // Successful acquisition is the assertion; we'd hit the IOException
            // path below if the contract were broken.
            Assert.NotNull(held);
        }

        [Fact]
        public async Task Acquire_WhenHeld_RetriesUntilReleased()
        {
            using var temp = new TempDir();
            var lockPath = Path.Join(temp.Path, "selections.json.lock");

            var first = await SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken);

            // Kick off a contender — it should park inside the backoff loop until
            // we dispose the holder, then proceed.
            var contender = SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken);

            // Give the contender a moment to land inside its retry loop, then
            // release. If the lock semantics are broken the contender would have
            // already completed by now.
            await Task.Delay(50, TestContext.Current.CancellationToken);
            Assert.False(contender.IsCompleted, "contender completed while lock was held");

            first.Dispose();

            using var second = await contender.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            Assert.NotNull(second);
        }

        [Fact]
        public async Task Acquire_AfterRelease_Succeeds()
        {
            using var temp = new TempDir();
            var lockPath = Path.Join(temp.Path, "selections.json.lock");

            (await SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken)).Dispose();

            // DeleteOnClose is what makes stale-lock recovery unnecessary, and the type's
            // remarks lean on it ("there is no stale-lock recovery code to maintain"). The
            // comment here used to claim it without asserting it, so dropping the flag would
            // have left a permanent lock file and still passed (#57).
            Assert.False(File.Exists(lockPath), "sentinel file survived dispose");

            using var second = await SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken);
            Assert.NotNull(second);
        }

        [Fact]
        public async Task Acquire_WhenHeldThroughout_EventuallyThrowsWithAnActionableMessage()
        {
            using var temp = new TempDir();
            var lockPath = Path.Join(temp.Path, "selections.json.lock");

            using var holder = await SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken);

            // The ~5.1s backoff ladder ending in a thrown IOException was never reached by
            // any test, so neither its message nor its behaviour under a genuinely stuck
            // peer was verified (#57).
            var ex = await Assert.ThrowsAsync<IOException>(
                () => SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken));

            Assert.Contains(lockPath, ex.Message, StringComparison.Ordinal);
            Assert.Contains("Another process may be holding it", ex.Message, StringComparison.Ordinal);

            // The IOException that actually blocked acquisition is preserved, not discarded.
            Assert.NotNull(ex.InnerException);
        }

        [Fact]
        public async Task Acquire_SerialisesConcurrentHolders()
        {
            using var temp = new TempDir();
            var lockPath = Path.Join(temp.Path, "selections.json.lock");

            // The lock's actual job is serialising FileCredentialManager's selections
            // read-modify-write. Assert mutual exclusion directly: overlapping critical
            // sections are what a broken lock produces.
            var inside = 0;
            var overlaps = 0;

            async Task Contend()
            {
                using var held = await SelectionsLock.AcquireAsync(lockPath, TestContext.Current.CancellationToken);
                if (Interlocked.Increment(ref inside) != 1)
                {
                    _ = Interlocked.Increment(ref overlaps);
                }

                await Task.Delay(15, TestContext.Current.CancellationToken);
                _ = Interlocked.Decrement(ref inside);
            }

            await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Contend()));

            Assert.Equal(0, overlaps);
            Assert.False(File.Exists(lockPath), "sentinel file survived the last dispose");
        }
    }
}

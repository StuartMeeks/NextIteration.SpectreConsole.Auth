namespace NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

/// <summary>
/// Small polling helper for the OS-native secret-store tests. A just-completed
/// <c>AddCredentialAsync</c> against the macOS Keychain or the Linux Secret
/// Service is not always immediately visible to the next lookup when two test
/// processes (multi-targeting) hit the same store concurrently — so an
/// add-then-delete can see the delete's lookup miss the item and return false.
/// That is a store-visibility timing artifact of the tests running side by
/// side, not a defect in the manager, so it is closed here rather than by
/// making the production delete path slower.
/// </summary>
internal static class RetryHelper
{
    /// <summary>
    /// Invokes <paramref name="action"/> until it returns <see langword="true"/>
    /// or the attempts are exhausted, pausing <paramref name="delayMs"/> between
    /// tries. Returns the last result — <see langword="false"/> only if every
    /// attempt failed, so a genuinely-absent target still fails the assertion.
    /// </summary>
    internal static async Task<bool> UntilTrueAsync(
        Func<Task<bool>> action,
        int maxAttempts = 20,
        int delayMs = 25)
    {
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            if (await action())
            {
                return true;
            }

            if (attempt < maxAttempts)
            {
                await Task.Delay(delayMs);
            }
        }

        return false;
    }

    /// <summary>
    /// Invokes <paramref name="action"/> until its result satisfies
    /// <paramref name="predicate"/> or the attempts are exhausted, and returns
    /// that result. Used for read-after-write against the OS secret stores,
    /// where a just-completed add isn't always immediately visible to the next
    /// query under concurrent (multi-targeted) test runs. Returns the last
    /// result even if the predicate never held, so the caller's assertion still
    /// reports the real failure rather than a timeout.
    /// </summary>
    internal static async Task<T> UntilAsync<T>(
        Func<Task<T>> action,
        Func<T, bool> predicate,
        int maxAttempts = 20,
        int delayMs = 25)
    {
        var result = await action();
        for (var attempt = 1; !predicate(result) && attempt < maxAttempts; attempt++)
        {
            await Task.Delay(delayMs);
            result = await action();
        }

        return result;
    }
}

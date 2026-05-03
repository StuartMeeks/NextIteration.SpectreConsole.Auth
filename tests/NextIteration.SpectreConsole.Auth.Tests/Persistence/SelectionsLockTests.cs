using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence;

public sealed class SelectionsLockTests
{
    [Fact]
    public async Task Acquire_WhenUncontended_Succeeds()
    {
        using var temp = new TempDir();
        var lockPath = Path.Combine(temp.Path, "selections.json.lock");

        using var held = await SelectionsLock.AcquireAsync(lockPath);

        // Successful acquisition is the assertion; we'd hit the IOException
        // path below if the contract were broken.
        Assert.NotNull(held);
    }

    [Fact]
    public async Task Acquire_WhenHeld_RetriesUntilReleased()
    {
        using var temp = new TempDir();
        var lockPath = Path.Combine(temp.Path, "selections.json.lock");

        var first = await SelectionsLock.AcquireAsync(lockPath);

        // Kick off a contender — it should park inside the backoff loop until
        // we dispose the holder, then proceed.
        var contender = SelectionsLock.AcquireAsync(lockPath);

        // Give the contender a moment to land inside its retry loop, then
        // release. If the lock semantics are broken the contender would have
        // already completed by now.
        await Task.Delay(50);
        Assert.False(contender.IsCompleted, "contender completed while lock was held");

        first.Dispose();

        using var second = await contender.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.NotNull(second);
    }

    [Fact]
    public async Task Acquire_AfterRelease_Succeeds()
    {
        using var temp = new TempDir();
        var lockPath = Path.Combine(temp.Path, "selections.json.lock");

        (await SelectionsLock.AcquireAsync(lockPath)).Dispose();

        // DeleteOnClose should clean up the sentinel file when the holder
        // disposes; a fresh acquirer must succeed without seeing a stale
        // lock.
        using var second = await SelectionsLock.AcquireAsync(lockPath);
        Assert.NotNull(second);
    }
}

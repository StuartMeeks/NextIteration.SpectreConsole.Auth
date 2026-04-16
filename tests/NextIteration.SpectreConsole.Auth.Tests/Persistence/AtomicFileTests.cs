using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence;

public sealed class AtomicFileTests
{
    [Fact]
    public async Task WriteAllTextAsync_WritesExpectedContent()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.txt");

        await AtomicFile.WriteAllTextAsync(target, "hello");

        Assert.Equal("hello", await File.ReadAllTextAsync(target));
    }

    [Fact]
    public async Task WriteAllBytesAsync_WritesExpectedBytes()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.bin");
        var payload = new byte[] { 0x00, 0x01, 0x02, 0xFE, 0xFF };

        await AtomicFile.WriteAllBytesAsync(target, payload);

        Assert.Equal(payload, await File.ReadAllBytesAsync(target));
    }

    [Fact]
    public async Task WriteAllTextAsync_NoTempFileLeftBehindAfterSuccess()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.txt");

        await AtomicFile.WriteAllTextAsync(target, "hello");

        // Only the final file should exist — no stray .tmp files.
        var files = Directory.GetFiles(temp.Path);
        Assert.Single(files);
        Assert.Equal(target, files[0]);
    }

    [Fact]
    public async Task WriteAllTextAsync_OverwritesExisting()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.txt");
        await File.WriteAllTextAsync(target, "original");

        await AtomicFile.WriteAllTextAsync(target, "replaced");

        Assert.Equal("replaced", await File.ReadAllTextAsync(target));
    }

    [Fact]
    public async Task WriteAllTextAsync_DoesNotExposeIntermediateState()
    {
        // Between the moment the temp file is fully written and the rename,
        // a concurrent observer should see either the old content or the new
        // content — never an empty/half-written target.
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.txt");
        await File.WriteAllTextAsync(target, "original");

        // Hard to probe the race deterministically, so at minimum assert
        // that the post-write state is fully the new content.
        await AtomicFile.WriteAllTextAsync(target, "replaced-content-that-is-longer");

        Assert.Equal("replaced-content-that-is-longer", await File.ReadAllTextAsync(target));
    }

    [Fact]
    public async Task WriteAllTextAsync_SetsUnixMode_OnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // Unix-only assertion; chmod is a no-op on Windows.
        }

        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.txt");

        await AtomicFile.WriteAllTextAsync(
            target,
            "secret",
            UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var mode = File.GetUnixFileMode(target);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
    }

    [Fact]
    public async Task WriteAllTextAsync_NullUnixMode_DoesNotThrow()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.txt");

        await AtomicFile.WriteAllTextAsync(target, "hello", unixMode: null);

        Assert.Equal("hello", await File.ReadAllTextAsync(target));
    }

    [Fact]
    public async Task WriteAllTextAsync_UsesUniqueTempName_SafeForConcurrentWriters()
    {
        // Two simultaneous writers to the same target must not collide on
        // a shared {target}.tmp name. The helper's unique temp name +
        // last-rename-wins semantic means both succeed; only one final
        // content persists.
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "file.txt");

        var tasks = new[]
        {
            AtomicFile.WriteAllTextAsync(target, "writer-a"),
            AtomicFile.WriteAllTextAsync(target, "writer-b"),
        };
        await Task.WhenAll(tasks);

        var final = await File.ReadAllTextAsync(target);
        Assert.True(final is "writer-a" or "writer-b", $"expected one of the two writes to win, got: {final}");

        // No stragglers.
        var files = Directory.GetFiles(temp.Path);
        Assert.Single(files);
    }
}

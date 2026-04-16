using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence;

public sealed class CredentialsDirectoryTests
{
    [Fact]
    public void Ensure_CreatesDirectory_WhenMissing()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "creds");
        Assert.False(Directory.Exists(target));

        CredentialsDirectory.Ensure(target);

        Assert.True(Directory.Exists(target));
    }

    [Fact]
    public void Ensure_CreatesNestedDirectory_WhenParentMissing()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "nested", "creds");
        Assert.False(Directory.Exists(target));

        CredentialsDirectory.Ensure(target);

        Assert.True(Directory.Exists(target));
    }

    [Fact]
    public void Ensure_NoOp_WhenDirectoryAlreadyExists()
    {
        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "creds");
        Directory.CreateDirectory(target);

        // Touch a marker file inside so we can verify the directory isn't
        // recreated (which would wipe contents).
        var marker = Path.Combine(target, "marker.txt");
        File.WriteAllText(marker, "hello");

        CredentialsDirectory.Ensure(target);

        Assert.True(Directory.Exists(target));
        Assert.True(File.Exists(marker));
        Assert.Equal("hello", File.ReadAllText(marker));
    }

    [Fact]
    public void Ensure_SetsUnixMode0700_OnFirstCreation()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // Unix-only: Windows uses ACLs, verified via the file-perm integration path.
        }

        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "creds");

        CredentialsDirectory.Ensure(target);

        var mode = File.GetUnixFileMode(target);
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            mode);
    }

    [Fact]
    public void Ensure_DoesNotChange_ExistingUnixMode()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var temp = new TempDir();
        var target = Path.Combine(temp.Path, "creds");
        Directory.CreateDirectory(target);

        // A deliberately-permissive mode that the library would never choose.
        var originalMode = UnixFileMode.UserRead
            | UnixFileMode.UserWrite
            | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead
            | UnixFileMode.GroupExecute;
        File.SetUnixFileMode(target, originalMode);

        CredentialsDirectory.Ensure(target);

        // Should respect consumer-chosen perms on an existing directory.
        Assert.Equal(originalMode, File.GetUnixFileMode(target));
    }
}

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence
{
    public sealed class CredentialsDirectoryTests
    {
        [Fact]
        public void Ensure_CreatesDirectory_WhenMissing()
        {
            using var temp = new TempDir();
            var target = Path.Join(temp.Path, "creds");
            Assert.False(Directory.Exists(target));

            CredentialsDirectory.Ensure(target);

            Assert.True(Directory.Exists(target));
        }

        [Fact]
        public void Ensure_CreatesNestedDirectory_WhenParentMissing()
        {
            using var temp = new TempDir();
            var target = Path.Join(temp.Path, "nested", "creds");
            Assert.False(Directory.Exists(target));

            CredentialsDirectory.Ensure(target);

            Assert.True(Directory.Exists(target));
        }

        [Fact]
        public void Ensure_NoOp_WhenDirectoryAlreadyExists()
        {
            using var temp = new TempDir();
            var target = Path.Join(temp.Path, "creds");
            Directory.CreateDirectory(target);

            // Touch a marker file inside so we can verify the directory isn't
            // recreated (which would wipe contents).
            var marker = Path.Join(target, "marker.txt");
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
                // Early return rather than Assert.SkipWhen: the analyzer uses this branch to
                // narrow the platform for the File.GetUnixFileMode calls below (CA1416).
                // The Windows ACL equivalent is Ensure_SetsHardenedAcl_OnFirstCreation.
                return;
            }

            using var temp = new TempDir();
            var target = Path.Join(temp.Path, "creds");

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
            var target = Path.Join(temp.Path, "creds");
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

        [Fact]
        [SupportedOSPlatform("windows")]
        public void Ensure_SetsHardenedAcl_OnFirstCreation()
        {
            Assert.SkipWhen(!OperatingSystem.IsWindows(), "Windows ACLs; Unix uses mode bits, covered above.");

            using var temp = new TempDir();
            var target = Path.Join(temp.Path, "creds");

            CredentialsDirectory.Ensure(target);

            // Nothing asserted this before. The comment on the Unix test claimed the ACL was
            // "verified via the file-perm integration path", and no such path existed
            // anywhere in the suite (#47) -- so a regression here (wrong SID, inheritance
            // left on, an ACE dropped) shipped green on all three platforms, while ACL
            // hardening is one of the two reasons CLAUDE.md keeps the Windows CI leg.
            var security = new DirectoryInfo(target).GetAccessControl();

            Assert.True(
                security.AreAccessRulesProtected,
                "inheritance must be disabled, or %USERPROFILE% ACEs still grant access here");

            var rules = security.GetAccessRules(
                includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

            var sids = rules.Cast<FileSystemAccessRule>()
                .Select(r => ((SecurityIdentifier)r.IdentityReference).Value)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            var currentUser = WindowsIdentity.GetCurrent().User!.Value;
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value;

            // Exactly the current user and SYSTEM -- no Administrators, no Users, nothing
            // inherited. Asserting the whole set, not just that ours is present, is what
            // catches an extra ACE being granted.
            string[] expected = [.. new[] { currentUser, system }.OrderBy(x => x, StringComparer.Ordinal)];
            string[] actual = [.. sids.OrderBy(x => x, StringComparer.Ordinal)];
            Assert.Equal(expected, actual);

            foreach (FileSystemAccessRule rule in rules)
            {
                Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
                Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            }
        }
    }
}

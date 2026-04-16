using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Spectre.Console.Auth.Persistence
{
    /// <summary>
    /// Creates the credentials directory with hardened filesystem permissions.
    /// Centralised so every write path through the library lands on the same
    /// ACL / mode rules regardless of whether the directory is created by the
    /// credential manager or lazily by the encryption backend.
    /// </summary>
    internal static class CredentialsDirectory
    {
        /// <summary>
        /// Ensures <paramref name="path"/> exists. On first creation:
        /// <list type="bullet">
        /// <item>Windows: inheritance disabled; only the current user and
        /// SYSTEM are granted full control.</item>
        /// <item>Unix: mode 0700 (owner read/write/execute only).</item>
        /// </list>
        /// If the directory already exists its permissions are left untouched
        /// so consumer customisation (or tightened perms) survives.
        /// </summary>
        internal static void Ensure(string path)
        {
            if (Directory.Exists(path))
                return;

            if (OperatingSystem.IsWindows())
            {
                CreateWithWindowsAcl(path);
            }
            else
            {
                Directory.CreateDirectory(path);
                File.SetUnixFileMode(
                    path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        [SupportedOSPlatform("windows")]
        private static void CreateWithWindowsAcl(string path)
        {
            var security = new DirectorySecurity();

            // Disable inheritance from the parent and drop any ACEs that
            // would have been inherited — this is what stops Administrators
            // or Users ACEs on %USERPROFILE% from granting access here.
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var currentUser = WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("Cannot determine current Windows user SID.");
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            // Grant SYSTEM full control so OS-level services (backup,
            // antivirus, imaging) keep working — consistent with how DPAPI
            // and Windows Credential Manager scope their storage. An attacker
            // with SYSTEM privileges on the host already has full access to
            // the machine by definition, so this grants nothing they do not
            // already have.
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            new DirectoryInfo(path).Create(security);
        }
    }
}

using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Encryption;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Persistence.Keychain;
using NextIteration.SpectreConsole.Auth.Persistence.Libsecret;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// One labelled line of <c>accounts info</c> output. <see cref="Warning"/>, when set,
    /// explains why the value weakens the store (e.g. a credentials directory readable by
    /// other users).
    /// </summary>
    internal sealed record CredentialStoreFact(string Label, string Value, string? Warning = null);

    /// <summary>
    /// Builds the <c>accounts info</c> description from the <see cref="ICredentialManager"/>
    /// that DI actually resolved, rather than from <see cref="CredentialStoreOptions"/>.
    /// </summary>
    /// <remarks>
    /// Describing the resolved instance is deliberate. The DPAPI setup in the README registers
    /// <see cref="FileCredentialManager"/> by hand without <c>AddCredentialStore</c>, so there
    /// are no options to read; and a custom <see cref="ICredentialEncryption"/> registered in
    /// the wrong order is silently ignored. Inspecting what is wired up reports both truthfully.
    /// Nothing here reads a secret or touches the OS secret stores, so the command cannot
    /// trigger an unlock prompt.
    /// </remarks>
    internal static class CredentialStoreDescriber
    {
        // Group and other permission bits. Any of them set on the credentials directory
        // widens the file backend's only security boundary beyond the owning user.
        private const UnixFileMode GroupOrOther =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        internal static IReadOnlyList<CredentialStoreFact> Describe(ICredentialManager credentialManager)
        {
            ArgumentNullException.ThrowIfNull(credentialManager);

            var facts = new List<CredentialStoreFact>();

            if (credentialManager is FileCredentialManager file)
            {
                DescribeFileBackend(file, facts);
            }
            else if (OperatingSystem.IsMacOS() && credentialManager is KeychainCredentialManager keychain)
            {
                DescribeKeychainBackend(keychain, facts);
            }
            else if (OperatingSystem.IsLinux() && credentialManager is LibsecretCredentialManager libsecret)
            {
                DescribeLibsecretBackend(libsecret, facts);
            }
            else
            {
                facts.Add(new("Backend", $"Custom ({credentialManager.GetType().FullName})"));
            }

            facts.Add(new("Library version", LibraryVersion()));
            facts.Add(new("Platform", $"{RuntimeInformation.OSDescription} ({RuntimeInformation.RuntimeIdentifier})"));

            return facts;
        }

        private static void DescribeFileBackend(FileCredentialManager file, List<CredentialStoreFact> facts)
        {
            var directory = file.CredentialsDirectoryPath;

            facts.Add(new("Backend", "Encrypted files"));
            facts.Add(new("Credentials directory", Path.GetFullPath(directory)));
            facts.Add(DescribeDirectoryPermissions(directory));

            switch (file.Encryption)
            {
                case LocalFileCredentialEncryption local:
                    facts.Add(new("Encryption", "AES-256-GCM (data key sealed with PBKDF2-HMAC-SHA256)"));
                    facts.Add(new("Keystore", Path.GetFullPath(local.KeystorePath) + (File.Exists(local.KeystorePath) ? string.Empty : " (not created yet)")));
                    facts.Add(local.HasAdditionalEntropy
                        ? new("Key binding", "AdditionalEntropy (hardened)")
                        : new("Key binding", "None (default; portable, protected by directory permissions)"));
                    break;

                case var encryption when OperatingSystem.IsWindows() && encryption is DpapiCredentialEncryption:
                    facts.Add(new("Encryption", "Windows DPAPI (current user scope)"));
                    facts.Add(new("Key binding", "Windows user profile"));
                    break;

                case var encryption:
                    facts.Add(new("Encryption", $"Custom ({encryption.GetType().FullName})"));
                    break;
            }

            facts.Add(new("Selections file", Path.GetFullPath(file.SelectionFilePath)));
        }

        [SupportedOSPlatform("macos")]
        private static void DescribeKeychainBackend(KeychainCredentialManager keychain, List<CredentialStoreFact> facts)
        {
            facts.Add(new("Backend", "macOS Keychain (experimental)"));
            facts.Add(new("App identifier", keychain.AppIdentifier));
            facts.Add(new("Items", $"Generic passwords, service '{keychain.AppIdentifier}.<provider>'"));
            facts.Add(new("Encryption", "Managed by macOS Keychain"));
        }

        [SupportedOSPlatform("linux")]
        private static void DescribeLibsecretBackend(LibsecretCredentialManager libsecret, List<CredentialStoreFact> facts)
        {
            facts.Add(new("Backend", "Secret Service via libsecret (experimental)"));
            facts.Add(new("App identifier", libsecret.AppIdentifier));
            facts.Add(new("Collection", libsecret.Collection));
            facts.Add(new("Encryption", "Managed by the Secret Service daemon"));
        }

        internal static CredentialStoreFact DescribeDirectoryPermissions(string directory)
        {
            const string label = "Directory permissions";

            try
            {
                if (OperatingSystem.IsWindows())
                {
                    var isProtected = new DirectoryInfo(directory).GetAccessControl().AreAccessRulesProtected;
                    return isProtected
                        ? new(label, "Explicit ACL (inheritance disabled)")
                        : new(label, "Inherited from parent folder",
                            Warning: "The credentials directory inherits its ACL, so other accounts may be able to read it.");
                }

                var mode = File.GetUnixFileMode(directory);
                var octal = Convert.ToString((int)mode & 0x1FF, 8).PadLeft(4, '0');
                return (mode & GroupOrOther) == 0
                    ? new(label, $"{octal} (owner only)")
                    : new(label, octal,
                        Warning: "The credentials directory is accessible to group or other users. Running 'chmod 700' on it restricts it to its owner.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
            {
                return new(label, "Unknown", Warning: $"Could not read the credentials directory's permissions: {ex.Message}");
            }
        }

        private static string LibraryVersion()
        {
            var assembly = typeof(CredentialStoreDescriber).Assembly;
            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?? assembly.GetName().Version?.ToString()
                ?? "unknown";

            // Drop the SourceLink "+<commit sha>" suffix; the version is what users quote.
            var plus = version.IndexOf('+', StringComparison.Ordinal);
            return plus < 0 ? version : version[..plus];
        }
    }
}

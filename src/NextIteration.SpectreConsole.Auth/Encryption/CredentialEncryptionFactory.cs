using System.Runtime.Versioning;

namespace NextIteration.SpectreConsole.Auth.Encryption
{
    /// <summary>
    /// Factory for creating platform-appropriate credential encryption implementations.
    /// </summary>
    public static class CredentialEncryptionFactory
    {
        /// <summary>
        /// Creates the default encryption implementation for the current platform.
        /// Today this is always <see cref="LocalFileCredentialEncryption"/>. In
        /// the future this may switch to an OS-native keychain on macOS/Linux
        /// automatically — see the solution TODO for the planned backends.
        /// </summary>
        /// <param name="credentialsDirectory">Credentials directory where the keystore will live.</param>
        /// <param name="additionalEntropy">
        /// Optional caller-supplied entropy passed to
        /// <see cref="LocalFileCredentialEncryption"/> — see its remarks for
        /// the security implications of supplying it.
        /// </param>
        public static ICredentialEncryption Create(string credentialsDirectory, byte[]? additionalEntropy = null)
        {
            return new LocalFileCredentialEncryption(credentialsDirectory, additionalEntropy);
        }

        /// <summary>
        /// Creates the file-based, cross-platform encryption implementation explicitly.
        /// </summary>
        /// <param name="credentialsDirectory">Credentials directory where the keystore will live.</param>
        /// <param name="additionalEntropy">
        /// Optional caller-supplied entropy passed to
        /// <see cref="LocalFileCredentialEncryption"/> — see its remarks for
        /// the security implications of supplying it.
        /// </param>
        public static ICredentialEncryption CreateLocalFile(string credentialsDirectory, byte[]? additionalEntropy = null)
        {
            return new LocalFileCredentialEncryption(credentialsDirectory, additionalEntropy);
        }

        /// <summary>
        /// Creates a Windows DPAPI encryption implementation. Windows only —
        /// calling this from non-Windows code is flagged by the analyzer
        /// (<c>CA1416</c>) and throws <see cref="PlatformNotSupportedException"/>
        /// at runtime.
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">Not running on Windows.</exception>
        [SupportedOSPlatform("windows")]
        public static ICredentialEncryption CreateDpapi()
        {
            return new DpapiCredentialEncryption();
        }
    }
}

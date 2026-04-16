namespace Spectre.Console.Auth.Encryption
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
        public static ICredentialEncryption Create(string credentialsDirectory)
        {
            return new LocalFileCredentialEncryption(credentialsDirectory);
        }

        /// <summary>
        /// Creates the file-based, cross-platform encryption implementation explicitly.
        /// </summary>
        /// <param name="credentialsDirectory">Credentials directory where the keystore will live.</param>
        public static ICredentialEncryption CreateLocalFile(string credentialsDirectory)
        {
            return new LocalFileCredentialEncryption(credentialsDirectory);
        }

        /// <summary>
        /// Creates a Windows DPAPI encryption implementation (Windows only).
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">Thrown when not running on Windows.</exception>
        public static ICredentialEncryption CreateDpapi()
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("DPAPI encryption is only available on Windows");
            }

            return new DpapiCredentialEncryption();
        }
    }
}

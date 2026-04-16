using System.Security.Cryptography;
using System.Text;

namespace Next.SpectreConsole.Auth.Encryption
{
    /// <summary>
    /// Uses Windows DPAPI (Data Protection API) for credential encryption.
    /// Credentials are encrypted using the current user's profile.
    /// Windows only.
    /// </summary>
    public class DpapiCredentialEncryption : ICredentialEncryption
    {
        /// <summary>
        /// Constructs a DPAPI-backed encryption. Throws on non-Windows platforms.
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">Not running on Windows.</exception>
        public DpapiCredentialEncryption()
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("DPAPI encryption is only available on Windows");
            }
        }

        /// <inheritdoc />
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Code only called when running on windows operating system.")]
        public Task<string> EncryptAsync(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return Task.FromResult(string.Empty);

            try
            {
                var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                var encryptedBytes = ProtectedData.Protect(
                    plainTextBytes,
                    null, // No additional entropy
                    DataProtectionScope.CurrentUser); // Encrypt for current user only

                return Task.FromResult(Convert.ToBase64String(encryptedBytes));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to encrypt credential data", ex);
            }
        }

        /// <inheritdoc />
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Code only called when running on windows operating system.")]
        public Task<string> DecryptAsync(string encryptedText)
        {
            if (string.IsNullOrEmpty(encryptedText))
                return Task.FromResult(string.Empty);

            try
            {
                var encryptedBytes = Convert.FromBase64String(encryptedText);
                var decryptedBytes = ProtectedData.Unprotect(
                    encryptedBytes,
                    null, // No additional entropy
                    DataProtectionScope.CurrentUser); // Decrypt for current user only

                return Task.FromResult(Encoding.UTF8.GetString(decryptedBytes));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to decrypt credential data", ex);
            }
        }
    }
}

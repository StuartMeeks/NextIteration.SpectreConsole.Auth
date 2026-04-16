namespace Next.SpectreConsole.Auth.Encryption
{
    /// <summary>
    /// Symmetric encryption contract for credential payloads. Implementations
    /// are expected to be authenticated (tamper-detecting) and to manage
    /// their own key material.
    /// </summary>
    public interface ICredentialEncryption
    {
        /// <summary>
        /// Encrypts the supplied plaintext and returns an opaque string
        /// suitable for storage. Returns an empty string if
        /// <paramref name="plainText"/> is null or empty.
        /// </summary>
        Task<string> EncryptAsync(string plainText);

        /// <summary>
        /// Reverses <see cref="EncryptAsync"/>. Throws
        /// <see cref="InvalidOperationException"/> if the ciphertext is
        /// malformed or fails an integrity check.
        /// </summary>
        Task<string> DecryptAsync(string encryptedText);
    }
}

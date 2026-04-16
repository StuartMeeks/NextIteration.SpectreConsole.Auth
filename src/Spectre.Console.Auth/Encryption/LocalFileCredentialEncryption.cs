using Spectre.Console.Auth.Persistence;
using System.Security.Cryptography;
using System.Text;

namespace Spectre.Console.Auth.Encryption
{
    /// <summary>
    /// File-based credential encryption using AES-GCM with a machine-derived
    /// key-encryption key. Works on Windows, macOS, and Linux, but is best
    /// thought of as obfuscation-plus-tamper-detection rather than strong
    /// protection against a local attacker — see remarks.
    /// </summary>
    /// <remarks>
    /// Authenticated encryption (AES-GCM) detects tampering on decrypt.
    /// <para>
    /// Security model: the data encryption key lives encrypted in a
    /// <c>.keystore</c> file inside the credentials directory. That file is
    /// encrypted with a KEK derived from <c>{MachineName}:{UserName}:{OSVersion}</c>
    /// via PBKDF2. Because all KEK inputs are discoverable on the machine, the
    /// real security boundary is the filesystem permissions on the credentials
    /// directory, not the cryptography. An attacker with read access to the
    /// keystore file on the same machine/user can derive the KEK and decrypt
    /// credentials. Use DPAPI (on Windows) or a platform keychain for stronger
    /// protection against local attackers.
    /// </para>
    /// </remarks>
    public class LocalFileCredentialEncryption : ICredentialEncryption
    {
        // AES-GCM standard sizes. 12-byte nonce and 16-byte tag are the
        // recommended defaults and the values NIST SP 800-38D specifies.
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32; // AES-256

        // PBKDF2-HMAC-SHA256 iteration count. OWASP 2023 guidance is 600,000.
        // Iterations provide no real benefit while the KEK inputs are all
        // machine-derived (an attacker with keystore access computes the KEK
        // directly, not via brute force), but this constant starts earning
        // its keep the moment the caller-supplied additional-entropy TODO
        // lands — at which point it protects the secret-mixed KEK against
        // offline brute force.
        private const int Pbkdf2Iterations = 600_000;

        private readonly string _keyFile;
        private readonly byte[] _additionalEntropy;

        // The data encryption key is derived once per instance lifetime and
        // cached. PBKDF2 at 600k iterations is ~150-200ms on modern hardware
        // so paying for it on every Encrypt/Decrypt would make bulk
        // operations (accounts list decrypting N credentials) painful.
        // Lazy<Task<T>> gives us thread-safe lazy initialisation and also
        // caches any initialisation failure — if the keystore is corrupt we
        // want to fail every call the same way, not re-try and succeed on
        // some while failing on others.
        private readonly Lazy<Task<byte[]>> _dataKey;

        /// <summary>
        /// Creates the encryption implementation backed by a keystore file
        /// inside <paramref name="credentialsDirectory"/>. The keystore is
        /// created on first encrypt/decrypt call if it does not already exist.
        /// </summary>
        /// <exception cref="ArgumentException">
        /// <paramref name="credentialsDirectory"/> is null, empty, or whitespace.
        /// </exception>
        public LocalFileCredentialEncryption(string credentialsDirectory)
        {
            if (string.IsNullOrWhiteSpace(credentialsDirectory))
                throw new ArgumentException("Credentials directory must be provided.", nameof(credentialsDirectory));

            _keyFile = Path.Combine(credentialsDirectory, ".keystore");

            // Salt for PBKDF2. Non-secret but stable per machine/user.
            _additionalEntropy = Encoding.UTF8.GetBytes($"{Environment.MachineName}:{Environment.UserName}");

            _dataKey = new Lazy<Task<byte[]>>(LoadOrCreateDataKeyAsync, LazyThreadSafetyMode.ExecutionAndPublication);
        }

        /// <inheritdoc />
        public async Task<string> EncryptAsync(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            try
            {
                var key = await GetOrCreateKeyAsync().ConfigureAwait(false);
                var plainBytes = Encoding.UTF8.GetBytes(plainText);
                return Convert.ToBase64String(EncryptWithGcm(key, plainBytes));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to encrypt credential data.", ex);
            }
        }

        /// <inheritdoc />
        public async Task<string> DecryptAsync(string encryptedText)
        {
            if (string.IsNullOrEmpty(encryptedText))
                return string.Empty;

            byte[] input;
            try
            {
                input = Convert.FromBase64String(encryptedText);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("Encrypted credential data is not valid base64.", ex);
            }

            try
            {
                var key = await GetOrCreateKeyAsync().ConfigureAwait(false);
                var plainBytes = DecryptWithGcm(key, input);
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new InvalidOperationException(
                    "Credential data failed integrity check. The file has been tampered with, or was encrypted with a different key (for example, the keystore was copied from another machine or user).",
                    ex);
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to decrypt credential data.", ex);
            }
        }

        private Task<byte[]> GetOrCreateKeyAsync() => _dataKey.Value;

        private async Task<byte[]> LoadOrCreateDataKeyAsync()
        {
            if (!File.Exists(_keyFile))
            {
                await CreateKeyFileAsync().ConfigureAwait(false);
            }

            var encryptedKey = await File.ReadAllBytesAsync(_keyFile).ConfigureAwait(false);
            var kek = DeriveKeyEncryptionKey();
            return DecryptWithGcm(kek, encryptedKey);
        }

        private async Task CreateKeyFileAsync()
        {
            var key = RandomNumberGenerator.GetBytes(KeySize);
            var kek = DeriveKeyEncryptionKey();
            var encryptedKey = EncryptWithGcm(kek, key);

            var directory = Path.GetDirectoryName(_keyFile);
            if (!string.IsNullOrEmpty(directory))
            {
                CredentialsDirectory.Ensure(directory);
            }

            // Atomic write: a partially-written keystore would render every
            // credential undecryptable, so this path is one we especially
            // want crash-safe.
            await AtomicFile.WriteAllBytesAsync(
                _keyFile,
                encryptedKey,
                OperatingSystem.IsWindows() ? null : UnixFileMode.UserRead | UnixFileMode.UserWrite).ConfigureAwait(false);
        }

        private byte[] DeriveKeyEncryptionKey()
        {
            // Inputs are non-secret (discoverable on the machine); PBKDF2
            // iterations provide no real protection here today. The security
            // boundary is filesystem permissions on the keystore file.
            var password = $"{Environment.MachineName}:{Environment.UserName}:{Environment.OSVersion}";
            return Rfc2898DeriveBytes.Pbkdf2(password, _additionalEntropy, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
        }

        /// <summary>
        /// Encrypts <paramref name="plaintext"/> with AES-GCM using <paramref name="key"/>.
        /// Output layout: <c>[nonce(12)][tag(16)][ciphertext]</c>.
        /// </summary>
        private static byte[] EncryptWithGcm(byte[] key, byte[] plaintext)
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

            var output = new byte[NonceSize + TagSize + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, output, 0, NonceSize);
            Buffer.BlockCopy(tag, 0, output, NonceSize, TagSize);
            Buffer.BlockCopy(ciphertext, 0, output, NonceSize + TagSize, ciphertext.Length);
            return output;
        }

        /// <summary>
        /// Reverses <see cref="EncryptWithGcm"/>. Throws <see cref="AuthenticationTagMismatchException"/>
        /// if the ciphertext or tag has been modified.
        /// </summary>
        private static byte[] DecryptWithGcm(byte[] key, byte[] input)
        {
            if (input.Length < NonceSize + TagSize)
                throw new InvalidOperationException("Encrypted payload is shorter than the AES-GCM header.");

            var nonce = new byte[NonceSize];
            var tag = new byte[TagSize];
            var ciphertextLength = input.Length - NonceSize - TagSize;
            var ciphertext = new byte[ciphertextLength];

            Buffer.BlockCopy(input, 0, nonce, 0, NonceSize);
            Buffer.BlockCopy(input, NonceSize, tag, 0, TagSize);
            Buffer.BlockCopy(input, NonceSize + TagSize, ciphertext, 0, ciphertextLength);

            var plaintext = new byte[ciphertextLength];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }
    }
}

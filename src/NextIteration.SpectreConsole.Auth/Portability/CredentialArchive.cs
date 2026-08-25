using System.Security.Cryptography;
using System.Text.Json;

using NextIteration.SpectreConsole.Auth.Persistence;

namespace NextIteration.SpectreConsole.Auth.Portability
{
    /// <summary>
    /// Serialises a set of <see cref="CredentialExport"/> records into a
    /// portable, passphrase-encrypted archive and back. The archive is
    /// backend-independent: the on-disk credential ciphertext is machine-bound,
    /// so an archive holds the <em>decrypted</em> payloads re-encrypted under a
    /// passphrase the user carries between machines.
    /// </summary>
    /// <remarks>
    /// The envelope is JSON with a random per-export salt; the payload is
    /// AES-256-GCM over PBKDF2-HMAC-SHA256(passphrase, salt). Layout of the
    /// encrypted payload is <c>[nonce(12)][tag(16)][ciphertext]</c> — the same
    /// convention as <see cref="Encryption.LocalFileCredentialEncryption"/>.
    /// </remarks>
    internal static class CredentialArchive
    {
        private const string FormatMarker = "nextiteration-credential-archive";
        private const string KdfMarker = "PBKDF2-HMAC-SHA256";
        private const int CurrentVersion = 1;

        private const int SaltSize = 16;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32; // AES-256
        private const int Pbkdf2Iterations = 600_000; // matches LocalFileCredentialEncryption / OWASP 2023

        // Bounds on the iteration count an archive may ask for on open. The field exists so
        // an archive written by a future build with a different cost still opens, but it
        // arrives from an untrusted file and feeds straight into PBKDF2, so it needs both
        // ends clamped:
        //   - the ceiling stops a hostile or corrupt archive specifying up to int.MaxValue
        //     and hanging `accounts import` on CPU before any passphrase check can fail;
        //   - the floor stops an archive advertising a work factor below what this library
        //     documents, which would silently weaken the key derivation on open.
        // The ceiling is a generous multiple of the current cost so a future increase still
        // opens without a code change (#53).
        private const int MinPbkdf2Iterations = Pbkdf2Iterations;
        private const int MaxPbkdf2Iterations = Pbkdf2Iterations * 20; // ~12M, seconds not hours

        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        /// <summary>
        /// Encrypts <paramref name="credentials"/> under <paramref name="passphrase"/>
        /// and returns the archive as a JSON string ready to write to disk.
        /// </summary>
        internal static string Serialize(IReadOnlyList<CredentialExport> credentials, string passphrase)
        {
            ArgumentNullException.ThrowIfNull(credentials);
            ArgumentException.ThrowIfNullOrEmpty(passphrase);

            var payload = new ArchivePayload
            {
                ExportedAtUtc = DateTime.UtcNow,
                Credentials = [.. credentials.Select(ArchiveCredential.From)],
            };

            var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload, _jsonOptions);
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);

            try
            {
                var encrypted = EncryptWithGcm(key, plaintext);

                var envelope = new ArchiveEnvelope
                {
                    Format = FormatMarker,
                    Version = CurrentVersion,
                    Kdf = KdfMarker,
                    Iterations = Pbkdf2Iterations,
                    Salt = Convert.ToBase64String(salt),
                    Payload = Convert.ToBase64String(encrypted),
                };

                return JsonSerializer.Serialize(envelope, _jsonOptions);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        /// <summary>
        /// Reverses <see cref="Serialize"/>. Throws
        /// <see cref="InvalidOperationException"/> when the input is not an
        /// archive, is an unsupported version, is corrupt, or the passphrase is
        /// wrong (integrity-check failure).
        /// </summary>
        internal static IReadOnlyList<CredentialExport> Deserialize(string bundle, string passphrase)
        {
            ArgumentException.ThrowIfNullOrEmpty(bundle);
            ArgumentException.ThrowIfNullOrEmpty(passphrase);

            ArchiveEnvelope? envelope;
            try
            {
                envelope = JsonSerializer.Deserialize<ArchiveEnvelope>(bundle, _jsonOptions);
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException("The file is not a valid credential archive.", ex);
            }

            if (envelope is null || !string.Equals(envelope.Format, FormatMarker, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The file is not a credential archive.");
            }

            if (envelope.Version != CurrentVersion)
            {
                throw new InvalidOperationException(
                    $"Unsupported credential archive version {envelope.Version}; this build understands version {CurrentVersion}.");
            }

            if (string.IsNullOrEmpty(envelope.Salt) || string.IsNullOrEmpty(envelope.Payload))
            {
                throw new InvalidOperationException("The credential archive is missing its salt or payload.");
            }

            byte[] salt;
            byte[] encrypted;
            try
            {
                salt = Convert.FromBase64String(envelope.Salt);
                encrypted = Convert.FromBase64String(envelope.Payload);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("The credential archive is corrupt (invalid base64).", ex);
            }

            // Honour the archive's stated iteration count so archives written by a future
            // build with a different cost still open. Absent (0) means a build that predates
            // the field, so fall back to the current default; anything outside the supported
            // band is rejected rather than clamped, because silently deriving with a
            // different work factor than the file asks for would just fail the tag check
            // with a misleading "wrong passphrase" message.
            var iterations = envelope.Iterations == 0 ? Pbkdf2Iterations : envelope.Iterations;
            if (iterations < MinPbkdf2Iterations || iterations > MaxPbkdf2Iterations)
            {
                throw new InvalidOperationException(
                    $"The credential archive requests {iterations} PBKDF2 iterations, outside the supported range " +
                    $"{MinPbkdf2Iterations}–{MaxPbkdf2Iterations}. The file is corrupt or was not written by this library.");
            }
            var key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, KeySize);

            byte[] plaintext;
            try
            {
                plaintext = DecryptWithGcm(key, encrypted);
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new InvalidOperationException(
                    "Could not decrypt the credential archive. The passphrase is wrong, or the file has been modified.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }

            try
            {
                var payload = JsonSerializer.Deserialize<ArchivePayload>(plaintext, _jsonOptions);
                var credentials = payload?.Credentials ?? [];
                return [.. credentials.Select(c => c.ToExport())];
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException("The credential archive decrypted but its contents are malformed.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        /// <summary>
        /// AES-GCM encrypt with output layout <c>[nonce(12)][tag(16)][ciphertext]</c>.
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
        /// Reverses <see cref="EncryptWithGcm"/>; throws
        /// <see cref="AuthenticationTagMismatchException"/> on a wrong key or
        /// tampered payload.
        /// </summary>
        private static byte[] DecryptWithGcm(byte[] key, byte[] input)
        {
            if (input.Length < NonceSize + TagSize)
            {
                throw new InvalidOperationException("The credential archive payload is shorter than the AES-GCM header.");
            }

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

        // Non-secret envelope written in clear so the archive is self-describing.
        private sealed class ArchiveEnvelope
        {
            public string Format { get; set; } = string.Empty;
            public int Version { get; set; }
            public string Kdf { get; set; } = string.Empty;
            public int Iterations { get; set; }
            public string Salt { get; set; } = string.Empty;
            public string Payload { get; set; } = string.Empty;
        }

        // The encrypted payload — never written to disk in the clear.
        private sealed class ArchivePayload
        {
            public DateTime ExportedAtUtc { get; set; }
            public List<ArchiveCredential> Credentials { get; set; } = [];
        }

        // Lenient DTO (settable, defaulted) so a slightly-off archive fails with
        // a clear message during mapping rather than a required-member throw.
        private sealed class ArchiveCredential
        {
            public string AccountId { get; set; } = string.Empty;
            public string AccountName { get; set; } = string.Empty;
            public string ProviderName { get; set; } = string.Empty;
            public string Environment { get; set; } = string.Empty;
            public string CredentialData { get; set; } = string.Empty;
            public DateTime CreatedAt { get; set; }
            public bool IsSelected { get; set; }

            public static ArchiveCredential From(CredentialExport c) => new()
            {
                AccountId = c.AccountId,
                AccountName = c.AccountName,
                ProviderName = c.ProviderName,
                Environment = c.Environment,
                CredentialData = c.CredentialData,
                CreatedAt = c.CreatedAt,
                IsSelected = c.IsSelected,
            };

            public CredentialExport ToExport() => new()
            {
                AccountId = AccountId,
                AccountName = AccountName,
                ProviderName = ProviderName,
                Environment = Environment,
                CredentialData = CredentialData,
                CreatedAt = CreatedAt,
                IsSelected = IsSelected,
            };
        }
    }
}

using System.Security.Cryptography;
using System.Text;

using NextIteration.SpectreConsole.Auth.Persistence;

namespace NextIteration.SpectreConsole.Auth.Encryption
{
    /// <summary>
    /// File-based credential encryption using AES-GCM with a key-encryption key
    /// derived from a random per-keystore salt. Works on Windows, macOS, and Linux.
    /// </summary>
    /// <remarks>
    /// Authenticated encryption (AES-GCM) detects tampering on decrypt.
    /// <para>
    /// <b>Default security model</b> (no caller-supplied entropy): the data
    /// encryption key lives encrypted in a <c>.keystore</c> file inside the
    /// credentials directory. That file is sealed with a KEK derived via PBKDF2
    /// from a random per-keystore salt (stored in the keystore header) and a
    /// fixed domain tag — no machine, user, or OS input. Every KEK input is
    /// therefore either random-but-stored or a constant, so the KEK is not a
    /// secret: the real security boundary is the filesystem permissions on the
    /// credentials directory. A consequence, by design, is that a default-mode
    /// credentials directory is <em>portable</em> — copied whole to another
    /// machine or user it still decrypts. Earlier versions folded machine/user
    /// (and once OS) identity into the KEK; that was only a tripwire, never a
    /// boundary — the identity is discoverable — and it broke the store on a
    /// machine rename or OS update, so it was removed.
    /// </para>
    /// <para>
    /// <b>Hardened mode</b>: supply <c>additionalEntropy</c> via the
    /// constructor (or <see cref="CredentialStoreOptions.AdditionalEntropy"/>).
    /// The entropy is mixed into the PBKDF2 password so the KEK depends on
    /// something an attacker cannot recover from the keystore alone — for
    /// example a per-deployment secret from an environment variable, hardware
    /// token, or HSM. This is the file backend's only real cryptographic
    /// boundary and the supported way to bind a store: the keystore file AND the
    /// entropy value are both required to decrypt. If machine binding is what
    /// you want, make the entropy a per-machine secret.
    /// </para>
    /// <para>
    /// For the strongest protection, use DPAPI (on Windows) or a platform
    /// keychain (macOS Keychain, Linux libsecret) instead — those bind to
    /// OS-managed secrets and survive a machine rename or OS update.
    /// </para>
    /// <para>
    /// The <c>.keystore</c> carries a format header (magic + one-byte version).
    /// Version 3 (current) stores a random salt and puts no identity in the KEK.
    /// Older keystores — version 2 (machine/user KEK), and version 1 plus legacy
    /// headerless (machine/user/OSVersion KEK) — are still read with their old
    /// KEK and then transparently re-sealed as version 3 on first load, so an
    /// existing, still-readable store migrates itself. A keystore written by
    /// this version is not readable by older library versions.
    /// </para>
    /// <para>
    /// Implements <see cref="IDisposable"/>: disposing zeroes the in-memory
    /// data key and any caller-supplied entropy. When registered in DI as a
    /// singleton (the default), this happens at container disposal.
    /// </para>
    /// </remarks>
    public class LocalFileCredentialEncryption : ICredentialEncryption, IDisposable
    {
        // AES-GCM standard sizes. 12-byte nonce and 16-byte tag are the
        // recommended defaults and the values NIST SP 800-38D specifies.
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32; // AES-256

        // Keystore file format header. A keystore is prefixed with this magic
        // and a one-byte format version. Keystores written by pre-header
        // library versions have no header (they begin with a random 12-byte
        // nonce); those are still read, since the 8-byte magic can't plausibly
        // collide with a random nonce prefix (~2^-64). A keystore written by
        // this version is not readable by older library versions.
        //
        // Version history of the KEK the data key is sealed under:
        //   v1 (and legacy headerless): {MachineName}:{UserName}:{OSVersion}.
        //     A Windows feature update changed OSVersion and broke the store.
        //   v2: {MachineName}:{UserName}:{tag}. OSVersion dropped, but machine
        //     and user name are still ambient inputs that break on a rename and
        //     are not a real boundary (they are discoverable).
        //   v3 (current): a random per-keystore salt (stored in the header)
        //     plus a fixed tag — no machine/user/OS input. See DeriveCurrentKek.
        // v3 layout is: magic | version(1) | salt(SaltSize) | AES-GCM payload.
        // v1/v2 have no salt field (their salt is derived from machine/user).
        //
        // A v1 or v2 keystore is read with its old KEK and transparently
        // re-sealed as v3 on first load. A version this build does not know is
        // rejected with a clear error rather than an opaque integrity failure.
        private static readonly byte[] KeystoreMagic = "NISCA-KS"u8.ToArray();
        private const byte LegacyOsVersionFormatVersion = 1;
        private const byte MachineBoundFormatVersion = 2;
        private const byte KeystoreFormatVersion = 3;

        // Random salt written into every v3 keystore header. 16 bytes is the
        // usual PBKDF2 salt size; it is non-secret and its only job is to make
        // each keystore's KEK independent and to give hardened-mode brute-force
        // a per-keystore cost.
        private const int SaltSize = 16;

        // PBKDF2-HMAC-SHA256 iteration count. OWASP 2023 guidance is
        // 600,000. In default mode (no caller entropy) iterations provide
        // little benefit because the KEK inputs are all non-secret; an
        // attacker with keystore access computes the KEK directly. In
        // hardened mode (caller entropy supplied) the iterations earn their
        // keep — they force the cost-per-guess on any offline brute-force
        // attempt against the caller-supplied secret.
        private const int Pbkdf2Iterations = 600_000;

        // Stable, non-secret domain tags folded into the KEK password. Each
        // marks a KEK scheme so a future KDF change can pick a new tag; v2 also
        // kept its password distinct from its machine/user salt. Both are kept
        // so existing v1/v2 keystores can still be read and migrated.
        private const string KekDomainV3 = "keystore/kek/v3";
        private const string KekDomainV2 = "keystore/kek/v2";

        private readonly string _keyFile;

        // The machine/user salt used by the v1 and v2 KEKs. Retained only to
        // read and migrate an existing v1/v2 keystore; v3 uses a random salt
        // from the header instead.
        private readonly byte[] _legacySalt;
        private readonly byte[]? _callerEntropy;

        // The data encryption key is derived once per instance lifetime and
        // cached. PBKDF2 at 600k iterations is ~150-200ms on modern hardware
        // so paying for it on every Encrypt/Decrypt would make bulk
        // operations (accounts list decrypting N credentials) painful.
        // Lazy<Task<T>> gives us thread-safe lazy initialisation and also
        // caches any initialisation failure — if the keystore is corrupt we
        // want to fail every call the same way, not re-try and succeed on
        // some while failing on others.
        private readonly Lazy<Task<byte[]>> _dataKey;
        private bool _disposed;

        /// <summary>
        /// Creates the encryption implementation backed by a keystore file
        /// inside <paramref name="credentialsDirectory"/>. The keystore is
        /// created on first encrypt/decrypt call if it does not already exist.
        /// </summary>
        /// <param name="credentialsDirectory">
        /// Directory where the <c>.keystore</c> file is (or will be) created.
        /// </param>
        /// <param name="additionalEntropy">
        /// Optional caller-supplied entropy mixed into the key-derivation
        /// step. When non-null and non-empty, the KEK depends on this value —
        /// the file-based backend then requires both the keystore file AND the
        /// entropy value to decrypt, and it is the only real cryptographic
        /// boundary the backend has. Changing the entropy invalidates any
        /// existing keystore; callers who rotate the value must delete the
        /// keystore and re-add credentials.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="credentialsDirectory"/> is null, empty, or whitespace.
        /// </exception>
        public LocalFileCredentialEncryption(string credentialsDirectory, byte[]? additionalEntropy = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(credentialsDirectory);

            _keyFile = Path.Join(credentialsDirectory, ".keystore");

            // Legacy (v1/v2) PBKDF2 salt — the machine/user string. Used only to
            // read an existing v1/v2 keystore for migration; v3 keystores carry
            // their own random salt in the header.
            _legacySalt = Encoding.UTF8.GetBytes($"{Environment.MachineName}:{Environment.UserName}");

            // Defensive copy — the caller may mutate or clear their buffer.
            _callerEntropy = additionalEntropy is { Length: > 0 }
                ? [.. additionalEntropy]
                : null;

            _dataKey = new Lazy<Task<byte[]>>(LoadOrCreateDataKeyAsync, LazyThreadSafetyMode.ExecutionAndPublication);
        }

        /// <inheritdoc />
        public async Task<string> EncryptAsync(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                return string.Empty;
            }

            try
            {
                var key = await GetOrCreateKeyAsync().ConfigureAwait(false);
                var plainBytes = Encoding.UTF8.GetBytes(plainText);
                return Convert.ToBase64String(EncryptWithGcm(key, plainBytes));
            }
            catch (InvalidOperationException)
            {
                // An already-actionable message (e.g. an unsupported keystore
                // format surfaced during lazy key load) should propagate as-is
                // rather than being re-wrapped as a generic encrypt failure.
                // Mirrors the same passthrough in DecryptAsync.
                throw;
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException("Failed to encrypt credential data.", ex);
            }
            catch (IOException ex)
            {
                throw new InvalidOperationException("Failed to read the keystore while encrypting credential data.", ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new InvalidOperationException("Failed to read the keystore while encrypting credential data.", ex);
            }
        }

        /// <inheritdoc />
        public async Task<string> DecryptAsync(string encryptedText)
        {
            if (string.IsNullOrEmpty(encryptedText))
            {
                return string.Empty;
            }

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
                // Message adapts to whether caller entropy is in play, so a
                // consumer who just changed their entropy knows where to look.
                var message = _callerEntropy is null
                    ? "Credential data failed integrity check. The keystore file is corrupt or has been tampered with (its header salt or ciphertext was modified)."
                    : "Credential data failed integrity check. The file has been tampered with, or was encrypted with a different additional-entropy value.";
                throw new InvalidOperationException(message, ex);
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException("Failed to decrypt credential data.", ex);
            }
            catch (IOException ex)
            {
                throw new InvalidOperationException("Failed to read the keystore while decrypting credential data.", ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new InvalidOperationException("Failed to read the keystore while decrypting credential data.", ex);
            }
        }

        private Task<byte[]> GetOrCreateKeyAsync() => _dataKey.Value;

        private async Task<byte[]> LoadOrCreateDataKeyAsync()
        {
            if (!File.Exists(_keyFile))
            {
                // Create-if-absent, and deliberately ignore whether we won: the read
                // below is what decides which key is used, so a racer that lost simply
                // adopts the winner's key instead of persisting data under a key that
                // is no longer on disk.
                await CreateKeyFileAsync().ConfigureAwait(false);
            }

            var stored = await File.ReadAllBytesAsync(_keyFile).ConfigureAwait(false);
            var (encryptedKey, version, headerSalt) = ParseKeystore(stored);

            // Pick the KEK for the version on disk. v3 uses the random header
            // salt and no identity; v2 the machine/user KEK; v1 (and headerless)
            // the machine/user/OSVersion KEK. A wrong KEK surfaces as
            // AuthenticationTagMismatchException here, which DecryptAsync turns
            // into the actionable integrity error.
            var kek = version switch
            {
                KeystoreFormatVersion => DeriveCurrentKek(headerSalt!),
                MachineBoundFormatVersion => DeriveV2Kek(),
                _ => DeriveLegacyOsVersionKek(),
            };

            var dataKey = DecryptWithGcm(kek, encryptedKey);

            if (version != KeystoreFormatVersion)
            {
                // Re-seal the recovered data key as v3 (random salt, no identity)
                // so a rename or OS update can't break the store. Best-effort:
                // the decrypt has already succeeded, so a persistence failure
                // must not fail the read.
                await TryMigrateToCurrentFormatAsync(dataKey).ConfigureAwait(false);
            }

            return dataKey;
        }

        /// <summary>
        /// Splits a keystore file into its AES-GCM payload, format version, and
        /// (for v3) the random KEK salt from the header. A header-carrying
        /// keystore begins with <see cref="KeystoreMagic"/> and a one-byte
        /// version; a v3 keystore then carries a <see cref="SaltSize"/>-byte
        /// salt before the payload, while v1/v2 have none (their salt is derived
        /// from machine/user, so the returned salt is <see langword="null"/>). A
        /// legacy headerless keystore has no header and is reported as
        /// <see cref="LegacyOsVersionFormatVersion"/>. Throws when a header is
        /// present but its version is not understood, so a keystore from a newer
        /// library fails clearly rather than as an opaque integrity error.
        /// </summary>
        private static (byte[] EncryptedKey, byte Version, byte[]? Salt) ParseKeystore(byte[] stored)
        {
            var headerLength = KeystoreMagic.Length + 1;
            if (stored.Length < headerLength ||
                !stored.AsSpan(0, KeystoreMagic.Length).SequenceEqual(KeystoreMagic))
            {
                // No recognisable header — a pre-header keystore, sealed under
                // the legacy OSVersion-based KEK.
                return (stored, LegacyOsVersionFormatVersion, null);
            }

            var version = stored[KeystoreMagic.Length];
            if (version is not (LegacyOsVersionFormatVersion or MachineBoundFormatVersion or KeystoreFormatVersion))
            {
                throw new InvalidOperationException(
                    $"Unsupported keystore format version {version}. This build supports versions {LegacyOsVersionFormatVersion}–{KeystoreFormatVersion}; the keystore was likely written by a newer version of the library.");
            }

            if (version != KeystoreFormatVersion)
            {
                // v1/v2: no salt field, payload follows the version byte directly.
                return (stored[headerLength..], version, null);
            }

            // v3: a random salt precedes the payload.
            if (stored.Length < headerLength + SaltSize)
            {
                throw new InvalidOperationException("Keystore is truncated: the version-3 salt is missing.");
            }

            var salt = stored[headerLength..(headerLength + SaltSize)];
            return (stored[(headerLength + SaltSize)..], version, salt);
        }

        private async Task CreateKeyFileAsync()
        {
            var key = RandomNumberGenerator.GetBytes(KeySize);
            var framed = SealDataKey(key);

            EnsureKeystoreDirectory();

            // Atomic AND exclusive. Crash-safety is why this is a temp-then-rename
            // (a half-written keystore would render every credential undecryptable);
            // exclusivity is why it must not overwrite.
            //
            // Two first-run invocations can both find no keystore and both mint a data
            // key — the ~200ms PBKDF2 derivation makes that window wide. If the second
            // write replaced the first, every credential the first process had already
            // encrypted would become permanently undecryptable. The loser instead
            // discards its key and LoadOrCreateDataKeyAsync re-reads the winner's file,
            // so both processes converge on one key and nothing is lost.
            _ = await AtomicFile.TryWriteNewAsync(
                _keyFile,
                framed,
                OperatingSystem.IsWindows() ? null : UnixFileMode.UserRead | UnixFileMode.UserWrite).ConfigureAwait(false);
        }

        /// <summary>
        /// Re-seals an already-recovered data key as a v3 keystore (random salt,
        /// no identity), upgrading a version-1, version-2, or legacy headerless
        /// keystore in place. Best-effort: any I/O or permission failure is
        /// swallowed because the caller already holds a valid in-memory data key
        /// and its read has succeeded — a persistence failure must not turn a
        /// working decrypt into an error. The next run retries the migration.
        /// </summary>
        private async Task TryMigrateToCurrentFormatAsync(byte[] dataKey)
        {
            try
            {
                var framed = SealDataKey(dataKey);
                EnsureKeystoreDirectory();

                // Overwrite is safe here, unlike the first-create path: the data
                // key is unchanged, so a racing migrator that re-seals the same
                // key under a fresh nonce loses nothing — only the KEK wrapping
                // and format version change.
                await AtomicFile.WriteAllBytesAsync(
                    _keyFile,
                    framed,
                    OperatingSystem.IsWindows() ? null : UnixFileMode.UserRead | UnixFileMode.UserWrite).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Swallowed by design — see the summary.
            }
        }

        /// <summary>
        /// Encrypts <paramref name="dataKey"/> under a fresh v3 KEK (a new random
        /// salt) and frames it as a v3 keystore:
        /// <c>magic | version | salt(SaltSize) | AES-GCM payload</c>, ready to
        /// write. A new salt each seal is why re-migrating the same data key is
        /// safe and idempotent.
        /// </summary>
        private byte[] SealDataKey(byte[] dataKey)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var encryptedKey = EncryptWithGcm(DeriveCurrentKek(salt), dataKey);

            var offset = KeystoreMagic.Length;
            var framed = new byte[offset + 1 + SaltSize + encryptedKey.Length];
            Buffer.BlockCopy(KeystoreMagic, 0, framed, 0, offset);
            framed[offset] = KeystoreFormatVersion;
            Buffer.BlockCopy(salt, 0, framed, offset + 1, SaltSize);
            Buffer.BlockCopy(encryptedKey, 0, framed, offset + 1 + SaltSize, encryptedKey.Length);
            return framed;
        }

        private void EnsureKeystoreDirectory()
        {
            var directory = Path.GetDirectoryName(_keyFile);
            if (!string.IsNullOrEmpty(directory))
            {
                CredentialsDirectory.Ensure(directory);
            }
        }

        /// <summary>
        /// Derives the current (v3) key-encryption key from the per-keystore
        /// random <paramref name="salt"/> and a fixed domain tag. No machine,
        /// user, or OS input — so a rename or OS update cannot rotate it, and a
        /// default-mode keystore is portable. Caller entropy, when present, is
        /// the only secret in the password and the only real boundary.
        /// </summary>
        private byte[] DeriveCurrentKek(byte[] salt)
            => DeriveKek(KekDomainV3, salt);

        /// <summary>
        /// Derives the version-2 KEK (machine/user identity plus a tag, salted
        /// by the machine/user string). Used only to read an existing v2
        /// keystore so it can be re-sealed as v3.
        /// </summary>
        private byte[] DeriveV2Kek()
            => DeriveKek($"{Environment.MachineName}:{Environment.UserName}:{KekDomainV2}", _legacySalt);

        /// <summary>
        /// Derives the version-1 KEK, which folded the volatile
        /// <see cref="Environment.OSVersion"/> into the identity. Used only to
        /// read an existing v1 (or legacy headerless) keystore so it can be
        /// re-sealed as v3.
        /// </summary>
        private byte[] DeriveLegacyOsVersionKek()
            => DeriveKek($"{Environment.MachineName}:{Environment.UserName}:{Environment.OSVersion}", _legacySalt);

        /// <summary>
        /// PBKDF2-HMAC-SHA256 over <paramref name="context"/> and
        /// <paramref name="salt"/>. Caller entropy, when present, is prepended to
        /// the context (null-separated) so it contributes to every HMAC block.
        /// </summary>
        private byte[] DeriveKek(string context, byte[] salt)
        {
            if (_callerEntropy is null)
            {
                // Default mode — the context is the whole password.
                return Rfc2898DeriveBytes.Pbkdf2(context, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
            }

            // Hardened mode — caller entropy is concatenated with a null
            // separator in front of the context. Using the byte overload rather
            // than string interpolation so caller-supplied bytes don't have to
            // be valid UTF-8.
            var contextBytes = Encoding.UTF8.GetBytes(context);
            var password = new byte[_callerEntropy.Length + 1 + contextBytes.Length];
            Buffer.BlockCopy(_callerEntropy, 0, password, 0, _callerEntropy.Length);
            password[_callerEntropy.Length] = 0x00;
            Buffer.BlockCopy(contextBytes, 0, password, _callerEntropy.Length + 1, contextBytes.Length);

            return Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
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
            {
                throw new InvalidOperationException("Encrypted payload is shorter than the AES-GCM header.");
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

        /// <summary>
        /// Zeroes the in-memory data key and caller-supplied entropy. Safe to
        /// call more than once.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Core disposal. Overriders should call the base implementation so the
        /// key material is still cleared.
        /// </summary>
        /// <param name="disposing">
        /// <see langword="true"/> when called from <see cref="Dispose()"/>.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                if (_callerEntropy is not null)
                {
                    CryptographicOperations.ZeroMemory(_callerEntropy);
                }

                // Only zero the cached key if it was actually derived and
                // completed successfully; touching a faulted/pending Task's
                // Result would throw or block.
                if (_dataKey.IsValueCreated && _dataKey.Value.IsCompletedSuccessfully)
                {
                    CryptographicOperations.ZeroMemory(_dataKey.Value.Result);
                }
            }

            _disposed = true;
        }
    }
}

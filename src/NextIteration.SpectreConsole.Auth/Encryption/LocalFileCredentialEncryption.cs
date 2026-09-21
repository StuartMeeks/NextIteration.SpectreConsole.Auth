using System.Security.Cryptography;
using System.Text;

using NextIteration.SpectreConsole.Auth.Persistence;

namespace NextIteration.SpectreConsole.Auth.Encryption
{
    /// <summary>
    /// File-based credential encryption using AES-GCM with a machine-derived
    /// key-encryption key. Works on Windows, macOS, and Linux.
    /// </summary>
    /// <remarks>
    /// Authenticated encryption (AES-GCM) detects tampering on decrypt.
    /// <para>
    /// <b>Default security model</b> (no caller-supplied entropy): the data
    /// encryption key lives encrypted in a <c>.keystore</c> file inside the
    /// credentials directory. That file is encrypted with a KEK derived via
    /// PBKDF2 from stable machine/user identity
    /// (<c>{MachineName}:{UserName}</c>). The OS version is deliberately
    /// <em>not</em> an input: it once was, but a Windows feature update then
    /// rotated the KEK and left the keystore unreadable, so it was removed
    /// (see the format/migration note below). Because all KEK inputs are
    /// discoverable on the machine, the real security boundary is the
    /// filesystem permissions on the credentials directory, not the
    /// cryptography. An attacker with read access to the keystore file on the
    /// same machine/user can derive the KEK and decrypt credentials.
    /// </para>
    /// <para>
    /// <b>Hardened mode</b>: supply <c>additionalEntropy</c> via the
    /// constructor (or <see cref="CredentialStoreOptions.AdditionalEntropy"/>).
    /// The entropy is mixed into the PBKDF2 password so the KEK depends on
    /// something an attacker cannot recover from the machine alone — for
    /// example a per-deployment secret from an environment variable,
    /// hardware token, or HSM. In this mode the keystore file alone is
    /// insufficient to decrypt; the entropy value must also be known.
    /// </para>
    /// <para>
    /// For the strongest protection, use DPAPI (on Windows) or a platform
    /// keychain (macOS Keychain, Linux libsecret) instead.
    /// </para>
    /// <para>
    /// The <c>.keystore</c> file written by this version carries a format
    /// header (magic + one-byte version). A version-1 keystore — sealed under
    /// the old OSVersion-based KEK — and a legacy headerless keystore are both
    /// still read, with the old KEK, and then transparently re-sealed as the
    /// current version so a later OS update cannot break them. A keystore
    /// written by this version is not readable by pre-header library versions.
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
        // this version is not readable by pre-header library versions.
        //
        // Version 1 sealed the data key under a KEK that included
        // Environment.OSVersion; a Windows feature update changed OSVersion and
        // left the keystore undecryptable with no migration path. Version 2
        // drops OSVersion from the KEK (see DeriveKeyEncryptionKey). A version-1
        // keystore — and a legacy headerless one, which used the same
        // OSVersion-based KEK — is read with the legacy KEK and then
        // transparently re-sealed as version 2 on first load, so an existing
        // store survives the upgrade and is immune to later OS updates. A
        // version this build does not know is rejected with a clear error
        // rather than surfacing as an opaque integrity-check failure.
        private static readonly byte[] KeystoreMagic = "NISCA-KS"u8.ToArray();
        private const byte LegacyOsVersionFormatVersion = 1;
        private const byte KeystoreFormatVersion = 2;

        // PBKDF2-HMAC-SHA256 iteration count. OWASP 2023 guidance is
        // 600,000. In default mode (no caller entropy) iterations provide
        // little benefit because the KEK inputs are all machine-derived; an
        // attacker with keystore access computes the KEK directly. In
        // hardened mode (caller entropy supplied) the iterations earn their
        // keep — they force the cost-per-guess on any offline brute-force
        // attempt against the caller-supplied secret.
        private const int Pbkdf2Iterations = 600_000;

        // Stable, non-secret domain tag folded into the version-2 KEK password.
        // It marks the OSVersion-free derivation (so a future KDF change can
        // pick a new tag) and keeps the PBKDF2 password from being byte-for-byte
        // the salt, which is the same machine/user string.
        private const string KekDomainV2 = "keystore/kek/v2";

        private readonly string _keyFile;
        private readonly byte[] _salt;
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
        /// step. When non-null and non-empty, the KEK depends on this value
        /// in addition to the machine-derived inputs — the file-based
        /// backend then requires both the keystore file AND the entropy
        /// value to decrypt. Changing the entropy invalidates any existing
        /// keystore; callers who rotate the value must delete the keystore
        /// and re-add credentials.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="credentialsDirectory"/> is null, empty, or whitespace.
        /// </exception>
        public LocalFileCredentialEncryption(string credentialsDirectory, byte[]? additionalEntropy = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(credentialsDirectory);

            _keyFile = Path.Join(credentialsDirectory, ".keystore");

            // PBKDF2 salt — non-secret, stable per machine/user. Caller
            // entropy is mixed into the password side instead of the salt
            // so it contributes to HMAC input during the key-stretch loop.
            _salt = Encoding.UTF8.GetBytes($"{Environment.MachineName}:{Environment.UserName}");

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
                    ? "Credential data failed integrity check. The file has been tampered with, or was encrypted with a different key (for example, the keystore was copied from another machine or user, or a Windows feature update changed the machine identity before this version — which no longer folds the OS version into the key — was installed)."
                    : "Credential data failed integrity check. The file has been tampered with, or was encrypted with a different additional-entropy value, or on a different machine.";
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
            var (encryptedKey, version) = ParseKeystore(stored);

            // Version 2 is sealed under the OSVersion-free KEK; version 1 (and a
            // legacy headerless keystore) under the old OSVersion-based KEK. A
            // wrong KEK surfaces as AuthenticationTagMismatchException here,
            // which DecryptAsync turns into the actionable integrity error.
            var kek = version == KeystoreFormatVersion
                ? DeriveKeyEncryptionKey()
                : DeriveLegacyKeyEncryptionKey();

            var dataKey = DecryptWithGcm(kek, encryptedKey);

            if (version != KeystoreFormatVersion)
            {
                // Re-seal the recovered data key under the current KEK so a
                // later OS update can't break the store. Best-effort: the
                // decrypt has already succeeded, so a persistence failure must
                // not fail the read.
                await TryMigrateToCurrentFormatAsync(dataKey).ConfigureAwait(false);
            }

            return dataKey;
        }

        /// <summary>
        /// Splits a keystore file into its AES-GCM payload and format version.
        /// A keystore written by a header-carrying version begins with
        /// <see cref="KeystoreMagic"/> followed by a one-byte version; a legacy
        /// headerless keystore has no header and is reported as
        /// <see cref="LegacyOsVersionFormatVersion"/> (it used the same
        /// OSVersion-based KEK). Throws when a header is present but its version
        /// is not understood, so a keystore from a newer library fails clearly
        /// rather than as an opaque integrity error.
        /// </summary>
        private static (byte[] EncryptedKey, byte Version) ParseKeystore(byte[] stored)
        {
            var headerLength = KeystoreMagic.Length + 1;
            if (stored.Length < headerLength ||
                !stored.AsSpan(0, KeystoreMagic.Length).SequenceEqual(KeystoreMagic))
            {
                // No recognisable header — a pre-header keystore, sealed under
                // the legacy OSVersion-based KEK.
                return (stored, LegacyOsVersionFormatVersion);
            }

            var version = stored[KeystoreMagic.Length];
            if (version is not (LegacyOsVersionFormatVersion or KeystoreFormatVersion))
            {
                throw new InvalidOperationException(
                    $"Unsupported keystore format version {version}. This build supports versions {LegacyOsVersionFormatVersion}–{KeystoreFormatVersion}; the keystore was likely written by a newer version of the library.");
            }

            return (stored[headerLength..], version);
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
        /// Re-seals an already-recovered data key under the current
        /// (OSVersion-free) KEK, upgrading a version-1 or legacy headerless
        /// keystore to the current format in place. Best-effort: any I/O or
        /// permission failure is swallowed because the caller already holds a
        /// valid in-memory data key and its read has succeeded — a persistence
        /// failure must not turn a working decrypt into an error. The next run
        /// retries the migration.
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
        /// Encrypts <paramref name="dataKey"/> under the current KEK and frames
        /// it with the current format header, ready to write as a keystore.
        /// </summary>
        private byte[] SealDataKey(byte[] dataKey)
        {
            var encryptedKey = EncryptWithGcm(DeriveKeyEncryptionKey(), dataKey);

            // Frame the payload with the format header so the version is
            // self-describing on the next read.
            var framed = new byte[KeystoreMagic.Length + 1 + encryptedKey.Length];
            Buffer.BlockCopy(KeystoreMagic, 0, framed, 0, KeystoreMagic.Length);
            framed[KeystoreMagic.Length] = KeystoreFormatVersion;
            Buffer.BlockCopy(encryptedKey, 0, framed, KeystoreMagic.Length + 1, encryptedKey.Length);
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
        /// Derives the current key-encryption key. The OS version is
        /// deliberately excluded: it changed on every Windows feature update
        /// (e.g. 25H2 → 26H2), which rotated the KEK and left the keystore
        /// undecryptable. Machine and user name still bind the keystore to this
        /// machine/user.
        /// </summary>
        private byte[] DeriveKeyEncryptionKey()
            => DeriveKek($"{Environment.MachineName}:{Environment.UserName}:{KekDomainV2}");

        /// <summary>
        /// Derives the pre-version-2 key-encryption key, which folded the
        /// volatile <see cref="Environment.OSVersion"/> into the identity. Used
        /// only to read an existing version-1 (or legacy headerless) keystore so
        /// it can be re-sealed under <see cref="DeriveKeyEncryptionKey"/>.
        /// </summary>
        private byte[] DeriveLegacyKeyEncryptionKey()
            => DeriveKek($"{Environment.MachineName}:{Environment.UserName}:{Environment.OSVersion}");

        private byte[] DeriveKek(string machineIdentity)
        {
            if (_callerEntropy is null)
            {
                // Default mode — the machine identity is the whole password.
                return Rfc2898DeriveBytes.Pbkdf2(machineIdentity, _salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
            }

            // Hardened mode — caller entropy is concatenated with a null
            // separator in front of the machine identity. Using the byte
            // overload rather than string interpolation so caller-supplied
            // bytes don't have to be valid UTF-8.
            var machineBytes = Encoding.UTF8.GetBytes(machineIdentity);
            var password = new byte[_callerEntropy.Length + 1 + machineBytes.Length];
            Buffer.BlockCopy(_callerEntropy, 0, password, 0, _callerEntropy.Length);
            password[_callerEntropy.Length] = 0x00;
            Buffer.BlockCopy(machineBytes, 0, password, _callerEntropy.Length + 1, machineBytes.Length);

            return Rfc2898DeriveBytes.Pbkdf2(password, _salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
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

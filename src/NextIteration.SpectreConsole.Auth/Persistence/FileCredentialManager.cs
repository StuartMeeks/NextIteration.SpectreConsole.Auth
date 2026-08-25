using System.Text.Json;

using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Encryption;

namespace NextIteration.SpectreConsole.Auth.Persistence
{
    /// <summary>
    /// Default <see cref="ICredentialManager"/> implementation backed by
    /// encrypted files in a single directory. Registered automatically by
    /// <c>AddCredentialStore</c>.
    /// </summary>
    public class FileCredentialManager : ICredentialManager
    {
        private static readonly JsonSerializerOptions _jsonOptions = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        private readonly string _credentialsDirectory;
        private readonly string _selectionFile;
        private readonly string _selectionLockFile;
        private readonly ICredentialEncryption _encryption;
        private readonly Dictionary<string, ICredentialSummaryProvider> _summaryProviders;

        /// <summary>
        /// Constructs the manager over <paramref name="credentialsDirectory"/>.
        /// Creates the directory with hardened permissions if it does not
        /// already exist.
        /// </summary>
        /// <param name="encryption">Encryption backend used for every payload.</param>
        /// <param name="credentialsDirectory">Absolute path to the credentials directory.</param>
        /// <param name="summaryProviders">Optional provider-specific summary renderers.</param>
        public FileCredentialManager(
            ICredentialEncryption encryption,
            string credentialsDirectory,
            IEnumerable<ICredentialSummaryProvider>? summaryProviders = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(credentialsDirectory);

            _encryption = encryption;
            _credentialsDirectory = credentialsDirectory;
            _selectionFile = Path.Join(_credentialsDirectory, "selections.json");
            _selectionLockFile = Path.Join(_credentialsDirectory, "selections.json.lock");
            _summaryProviders = (summaryProviders ?? [])
                .ToDictionary(p => p.ProviderName, StringComparer.OrdinalIgnoreCase);

            EnsureDirectoryExists();
        }

        /// <inheritdoc />
        public async Task<IEnumerable<CredentialSummary>> ListCredentialsAsync(string providerName)
        {
            ValidateProviderName(providerName);

            // Scope the glob to this provider's files so we don't read blobs
            // belonging to other providers. Provider name is validated (S5)
            // and lowercased at write time, so the glob pattern is safe.
            var providerPrefix = providerName.ToLowerInvariant();
            var credentialFiles = Directory.GetFiles(_credentialsDirectory, $"{providerPrefix}_*.json");

            var credentials = new List<CredentialSummary>();
            var selections = await LoadSelectionsAsync().ConfigureAwait(false);
            _ = _summaryProviders.TryGetValue(providerName, out var summaryProvider);

            foreach (var file in credentialFiles)
            {
                StoredCredential? credential;
                try
                {
                    var content = await File.ReadAllTextAsync(file).ConfigureAwait(false);
                    credential = JsonSerializer.Deserialize<StoredCredential>(content, _jsonOptions);
                }
                catch (JsonException)
                {
                    // Skip invalid JSON files. Scoped to the deserialize step on purpose:
                    // this catch used to span the whole body, including the consumer's
                    // GetDisplayFields call, so a summary provider that threw JsonException
                    // silently removed the credential from the listing entirely (#52).
                    continue;
                }

                // Defensive re-check: the glob should only match this provider's files,
                // but if a stray file sneaks in we want to ignore it rather than report
                // a mis-attributed row.
                if (credential is null ||
                    !credential.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var isSelected = selections.TryGetValue($"{credential.ProviderName}", out var selectedId) &&
                               selectedId.Equals(credential.AccountId, StringComparison.OrdinalIgnoreCase);

                IReadOnlyList<KeyValuePair<string, string>> displayFields = [];
                var isRenderable = true;
                if (summaryProvider is not null)
                {
                    try
                    {
                        var decrypted = await _encryption.DecryptAsync(credential.CredentialData).ConfigureAwait(false);
                        displayFields = summaryProvider.GetDisplayFields(decrypted);
                    }
                    catch (InvalidOperationException)
                    {
                        // The payload cannot be opened with this machine's keystore —
                        // typically a credentials directory copied from another machine or
                        // user, or a keystore replaced while its credential files survived.
                        isRenderable = false;
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        // GetDisplayFields is consumer code and can throw anything; the
                        // README's own worked example deserializes with System.Text.Json,
                        // so an old payload shape throws JsonException here. A broken
                        // projection must cost this row its provider columns, never its
                        // existence — the user still needs the id to run `accounts delete`.
                        displayFields = [];
                        isRenderable = false;
                    }
                }

                credentials.Add(new CredentialSummary
                {
                    AccountId = credential.AccountId,
                    AccountName = credential.AccountName,
                    ProviderName = credential.ProviderName,
                    Environment = credential.Environment,
                    CreatedAt = credential.CreatedAt,
                    IsSelected = isSelected,
                    DisplayFields = displayFields,
                    IsDecryptable = isRenderable,
                });
            }

            return credentials.OrderBy(c => c.AccountName);
        }

        /// <inheritdoc />
        public async Task<string> AddCredentialAsync(string providerName, string accountName, string environment, string credentialData)
        {
            ValidateProviderName(providerName);

            var accountId = Guid.NewGuid().ToString();

            // Encrypt the credential data before storing
            var encryptedCredentialData = await _encryption.EncryptAsync(credentialData).ConfigureAwait(false);

            var credential = new StoredCredential
            {
                AccountId = accountId,
                AccountName = accountName,
                ProviderName = providerName,
                Environment = environment,
                CredentialData = encryptedCredentialData,
                CreatedAt = DateTime.UtcNow,
            };

            var fileName = $"{providerName.ToLowerInvariant()}_{accountId}.json";
            var filePath = Path.Join(_credentialsDirectory, fileName);

            var json = JsonSerializer.Serialize(credential, _jsonOptions);

            // Atomic write: a partial file is never observable even if we
            // crash mid-write. On Unix we also force 0600; on Windows the
            // file inherits the credentials-directory ACL.
            await AtomicFile.WriteAllTextAsync(
                filePath,
                json,
                OperatingSystem.IsWindows() ? null : UnixFileMode.UserRead | UnixFileMode.UserWrite).ConfigureAwait(false);

            return accountId;
        }

        /// <inheritdoc />
        public async Task<bool> DeleteCredentialAsync(string accountId)
        {
            if (!IsValidAccountId(accountId))
            {
                return false;
            }

            var found = await FindCredentialByAccountIdAsync(accountId).ConfigureAwait(false);
            if (found is null)
            {
                return false;
            }

            var (filePath, credential) = found.Value;
            File.Delete(filePath);

            // Hold the selections lock across load+modify+save so a concurrent
            // select/delete on a different provider can't lose its update.
            using var selectionsLock = await SelectionsLock.AcquireAsync(_selectionLockFile).ConfigureAwait(false);
            var selections = await LoadSelectionsAsync().ConfigureAwait(false);
            if (selections.TryGetValue(credential.ProviderName, out var selectedId) &&
                selectedId.Equals(accountId, StringComparison.OrdinalIgnoreCase))
            {
                _ = selections.Remove(credential.ProviderName);
                await SaveSelectionsAsync(selections).ConfigureAwait(false);
            }

            return true;
        }

        /// <inheritdoc />
        public async Task<bool> SelectCredentialAsync(string accountId)
        {
            if (!IsValidAccountId(accountId))
            {
                return false;
            }

            var found = await FindCredentialByAccountIdAsync(accountId).ConfigureAwait(false);
            if (found is null)
            {
                return false;
            }

            var credential = found.Value.Credential;
            using var selectionsLock = await SelectionsLock.AcquireAsync(_selectionLockFile).ConfigureAwait(false);
            var selections = await LoadSelectionsAsync().ConfigureAwait(false);
            selections[credential.ProviderName] = accountId;
            await SaveSelectionsAsync(selections).ConfigureAwait(false);
            return true;
        }

        /// <inheritdoc />
        public async Task<string?> GetSelectedCredentialAsync(string providerName)
        {
            ValidateProviderName(providerName);

            var selections = await LoadSelectionsAsync().ConfigureAwait(false);
            if (!selections.TryGetValue(providerName, out var selectedId) || !IsValidAccountId(selectedId))
            {
                // A non-GUID id can only land here via tampered selections.json;
                // treat it as "no selection" rather than letting a malformed
                // string flow into Path.Join.
                return null;
            }

            return await ReadAndDecryptByIdAsync(providerName, selectedId).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<string?> GetCredentialByIdAsync(string providerName, string accountId)
        {
            ValidateProviderName(providerName);
            ValidateAccountId(accountId);

            return await ReadAndDecryptByIdAsync(providerName, accountId).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads and decrypts a specific credential file by its deterministic
        /// <c>{provider}_{accountId}.json</c> path. Returns <see langword="null"/>
        /// when the file doesn't exist or its contents don't round-trip
        /// through the JSON + encryption layers. Shared by
        /// <see cref="GetSelectedCredentialAsync"/> (which first resolves
        /// the account id from <c>selections.json</c>) and
        /// <see cref="GetCredentialByIdAsync"/> (which takes it directly).
        /// </summary>
        private async Task<string?> ReadAndDecryptByIdAsync(string providerName, string accountId)
        {
            var fileName = $"{providerName.ToLowerInvariant()}_{accountId}.json";
            var filePath = Path.Join(_credentialsDirectory, fileName);
            if (!File.Exists(filePath))
            {
                return null;
            }

            StoredCredential? credential;
            try
            {
                var content = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);
                credential = JsonSerializer.Deserialize<StoredCredential>(content, _jsonOptions);
            }
            catch (JsonException)
            {
                return null;
            }

            return credential is null ? null : await _encryption.DecryptAsync(credential.CredentialData).ConfigureAwait(false);
        }

        /// <summary>
        /// Finds the stored credential with the given accountId by globbing the
        /// credentials directory for <c>*_{accountId}.json</c>. AccountIds are
        /// GUIDs so the pattern is expected to match at most one file.
        /// </summary>
        private async Task<(string FilePath, StoredCredential Credential)?> FindCredentialByAccountIdAsync(string accountId)
        {
            var matches = Directory.GetFiles(_credentialsDirectory, $"*_{accountId}.json");
            foreach (var file in matches)
            {
                try
                {
                    var content = await File.ReadAllTextAsync(file).ConfigureAwait(false);
                    var credential = JsonSerializer.Deserialize<StoredCredential>(content, _jsonOptions);
                    if (credential is not null &&
                        credential.AccountId.Equals(accountId, StringComparison.OrdinalIgnoreCase))
                    {
                        return (file, credential);
                    }
                }
                catch (JsonException)
                {
                    // Skip invalid JSON; try any other match.
                }
            }

            return null;
        }

        /// <inheritdoc />
        public async Task<IEnumerable<string>> GetProviderNamesAsync()
        {
            var credentialFiles = Directory.GetFiles(_credentialsDirectory, "*.json")
                .Where(f => !f.Equals(_selectionFile, StringComparison.OrdinalIgnoreCase));

            var providers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var file in credentialFiles)
            {
                try
                {
                    var content = await File.ReadAllTextAsync(file).ConfigureAwait(false);
                    var credential = JsonSerializer.Deserialize<StoredCredential>(content, _jsonOptions);

                    if (!string.IsNullOrWhiteSpace(credential?.ProviderName))
                    {
                        _ = providers.Add(credential.ProviderName);
                    }
                }
                catch (JsonException)
                {
                    // Skip invalid JSON files
                }
            }

            return providers.OrderBy(p => p);
        }

        /// <inheritdoc />
        public async Task<IReadOnlyList<CredentialExport>> ExportCredentialsAsync()
        {
            // Every *.json in the directory except the selection record is a
            // stored credential; mirrors the glob GetProviderNamesAsync uses.
            var credentialFiles = Directory.GetFiles(_credentialsDirectory, "*.json")
                .Where(f => !f.Equals(_selectionFile, StringComparison.OrdinalIgnoreCase));

            var selections = await LoadSelectionsAsync().ConfigureAwait(false);
            var exports = new List<CredentialExport>();

            foreach (var file in credentialFiles)
            {
                StoredCredential? credential;
                try
                {
                    var content = await File.ReadAllTextAsync(file).ConfigureAwait(false);
                    credential = JsonSerializer.Deserialize<StoredCredential>(content, _jsonOptions);
                }
                catch (JsonException)
                {
                    // Skip invalid JSON files (e.g. a stray .tmp that lost its race).
                    continue;
                }

                if (credential is null)
                {
                    continue;
                }

                var isSelected = selections.TryGetValue(credential.ProviderName, out var selectedId) &&
                    selectedId.Equals(credential.AccountId, StringComparison.OrdinalIgnoreCase);

                string decrypted;
                try
                {
                    decrypted = await _encryption.DecryptAsync(credential.CredentialData).ConfigureAwait(false);
                }
                catch (InvalidOperationException)
                {
                    // Unreadable ciphertext: skip rather than abort. One credential
                    // the local keystore cannot open must not veto an export of the
                    // rest, nor an import that only needs this metadata.
                    //
                    // Dropped rather than emitted with an empty payload on purpose —
                    // CredentialData flows straight into the archive, so an empty
                    // secret would become silent corruption at the next import.
                    // The caller reports the count instead.
                    continue;
                }

                exports.Add(new CredentialExport
                {
                    AccountId = credential.AccountId,
                    AccountName = credential.AccountName,
                    ProviderName = credential.ProviderName,
                    Environment = credential.Environment,
                    CredentialData = decrypted,
                    CreatedAt = credential.CreatedAt,
                    IsSelected = isSelected,
                });
            }

            return exports;
        }

        /// <inheritdoc />
        public async Task RestoreCredentialAsync(CredentialExport credential)
        {
            ArgumentNullException.ThrowIfNull(credential);

            // credential comes from an imported archive — untrusted input, so
            // both fields that flow into the file path are validated before use.
            ValidateProviderName(credential.ProviderName);
            ValidateAccountId(credential.AccountId);

            var encryptedCredentialData = await _encryption.EncryptAsync(credential.CredentialData).ConfigureAwait(false);

            var stored = new StoredCredential
            {
                AccountId = credential.AccountId,
                AccountName = credential.AccountName,
                ProviderName = credential.ProviderName,
                Environment = credential.Environment,
                CredentialData = encryptedCredentialData,
                CreatedAt = credential.CreatedAt,
            };

            var fileName = $"{credential.ProviderName.ToLowerInvariant()}_{credential.AccountId}.json";
            var filePath = Path.Join(_credentialsDirectory, fileName);

            var json = JsonSerializer.Serialize(stored, _jsonOptions);

            // Atomic write to the deterministic path replaces any existing
            // credential with the same provider + account id, so a re-import
            // is idempotent rather than duplicating.
            await AtomicFile.WriteAllTextAsync(
                filePath,
                json,
                OperatingSystem.IsWindows() ? null : UnixFileMode.UserRead | UnixFileMode.UserWrite).ConfigureAwait(false);

            if (credential.IsSelected)
            {
                using var selectionsLock = await SelectionsLock.AcquireAsync(_selectionLockFile).ConfigureAwait(false);
                var selections = await LoadSelectionsAsync().ConfigureAwait(false);
                selections[credential.ProviderName] = credential.AccountId;
                await SaveSelectionsAsync(selections).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Restricts the set of characters allowed in a provider name so it is
        /// safe to use as a filename prefix. Prevents path-traversal attacks
        /// via maliciously constructed provider names.
        /// </summary>
        private static void ValidateProviderName(string providerName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

            if (providerName.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '.' && c != '_' && c != '-'))
            {
                throw new ArgumentException(
                    $"Provider name '{providerName}' contains invalid characters. Allowed: ASCII letters, digits, '.', '_', '-'.",
                    nameof(providerName));
            }
        }

        /// <summary>
        /// Library-generated account ids are always GUIDs. Caller-supplied
        /// strings are constrained to that shape so they can't smuggle glob
        /// metacharacters (<c>*</c>, <c>?</c>) or path-traversal segments
        /// (<c>..</c>) into the file lookups.
        /// </summary>
        private static bool IsValidAccountId(string? accountId) =>
            !string.IsNullOrWhiteSpace(accountId) && Guid.TryParse(accountId, out _);

        /// <summary>
        /// Throwing variant of <see cref="IsValidAccountId"/> used at API
        /// boundaries where a malformed id is a programmer error rather than
        /// a "not found" condition.
        /// </summary>
        private static void ValidateAccountId(string accountId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(accountId);
            if (!Guid.TryParse(accountId, out _))
            {
                throw new ArgumentException(
                    $"Account id '{accountId}' is not a valid GUID.",
                    nameof(accountId));
            }
        }

        private void EnsureDirectoryExists() => CredentialsDirectory.Ensure(_credentialsDirectory);

        /// <summary>
        /// Loads the provider-to-account-id selection map, keyed case-insensitively.
        /// </summary>
        /// <remarks>
        /// The comparer is load-bearing. Every other provider-name comparison in this
        /// class is <see cref="StringComparison.OrdinalIgnoreCase"/> and the file glob is
        /// lowercased, but the selection map deserialised into a default (ordinal)
        /// dictionary — so <see cref="GetSelectedCredentialAsync"/> missed a selection
        /// stored under a differently-cased spelling while
        /// <see cref="ListCredentialsAsync"/> still reported that same credential as
        /// selected. A green tick in `accounts list` alongside "no credential selected"
        /// from the consumer's authenticate call (#48).
        /// </remarks>
        private async Task<Dictionary<string, string>> LoadSelectionsAsync()
        {
            if (!File.Exists(_selectionFile))
            {
                return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }

            Dictionary<string, string>? loaded;
            try
            {
                var content = await File.ReadAllTextAsync(_selectionFile).ConfigureAwait(false);
                loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(content, _jsonOptions);
            }
            catch (JsonException)
            {
                loaded = null;
            }

            var selections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (loaded is null)
            {
                return selections;
            }

            foreach (var (provider, accountId) in loaded)
            {
                // TryAdd rather than the indexer: a hand-edited selections.json can hold
                // two keys differing only by case, which would throw on a case-insensitive
                // dictionary. First wins, matching the file-enumeration order elsewhere.
                _ = selections.TryAdd(provider, accountId);
            }

            return selections;
        }

        private async Task SaveSelectionsAsync(Dictionary<string, string> selections)
        {
            var json = JsonSerializer.Serialize(selections, _jsonOptions);

            // Atomic write: selections.json is read-modify-written, and a
            // half-written file would be read as empty on next load and
            // then silently overwrite all selections. Atomic rename makes
            // crash-mid-write a non-issue.
            await AtomicFile.WriteAllTextAsync(
                _selectionFile,
                json,
                OperatingSystem.IsWindows() ? null : UnixFileMode.UserRead | UnixFileMode.UserWrite).ConfigureAwait(false);
        }

        private sealed class StoredCredential
        {
            public required string AccountId { get; init; }
            public required string AccountName { get; init; }
            public required string ProviderName { get; init; }
            public required string Environment { get; init; }
            public required string CredentialData { get; init; }
            public required DateTime CreatedAt { get; init; }
        }
    }
}

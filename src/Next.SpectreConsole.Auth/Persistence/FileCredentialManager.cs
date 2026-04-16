using System.Text.Json;

using Next.SpectreConsole.Auth.Commands;
using Next.SpectreConsole.Auth.Encryption;

namespace Next.SpectreConsole.Auth.Persistence
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
            if (string.IsNullOrWhiteSpace(credentialsDirectory))
            {
                throw new ArgumentException("Credentials directory must be provided.", nameof(credentialsDirectory));
            }

            _encryption = encryption;
            _credentialsDirectory = credentialsDirectory;
            _selectionFile = Path.Combine(_credentialsDirectory, "selections.json");
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
                try
                {
                    var content = await File.ReadAllTextAsync(file).ConfigureAwait(false);
                    var credential = JsonSerializer.Deserialize<StoredCredential>(content, _jsonOptions);

                    // Defensive re-check: the glob should only match this
                    // provider's files, but if a stray file sneaks in we want
                    // to ignore it rather than report a mis-attributed row.
                    if (credential?.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        var isSelected = selections.TryGetValue($"{credential.ProviderName}", out var selectedId) &&
                                       selectedId.Equals(credential.AccountId, StringComparison.OrdinalIgnoreCase);

                        IReadOnlyList<KeyValuePair<string, string>> displayFields = [];
                        if (summaryProvider is not null)
                        {
                            var decrypted = await _encryption.DecryptAsync(credential.CredentialData).ConfigureAwait(false);
                            displayFields = summaryProvider.GetDisplayFields(decrypted);
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
                        });
                    }
                }
                catch (JsonException)
                {
                    // Skip invalid JSON files
                }
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
            var filePath = Path.Combine(_credentialsDirectory, fileName);

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
            var found = await FindCredentialByAccountIdAsync(accountId).ConfigureAwait(false);
            if (found is null)
            {
                return false;
            }

            var (filePath, credential) = found.Value;
            File.Delete(filePath);

            // Remove the selection entry if it pointed at this credential.
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
            var found = await FindCredentialByAccountIdAsync(accountId).ConfigureAwait(false);
            if (found is null)
            {
                return false;
            }

            var credential = found.Value.Credential;
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
            if (!selections.TryGetValue(providerName, out var selectedId))
            {
                return null;
            }

            // Filename is deterministic given provider + accountId, so we can
            // read the one file directly rather than scanning the directory.
            var fileName = $"{providerName.ToLowerInvariant()}_{selectedId}.json";
            var filePath = Path.Combine(_credentialsDirectory, fileName);
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

        /// <summary>
        /// Restricts the set of characters allowed in a provider name so it is
        /// safe to use as a filename prefix. Prevents path-traversal attacks
        /// via maliciously constructed provider names.
        /// </summary>
        private static void ValidateProviderName(string providerName)
        {
            if (string.IsNullOrWhiteSpace(providerName))
            {
                throw new ArgumentException("Provider name must be non-empty.", nameof(providerName));
            }

            foreach (var c in providerName)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c != '.' && c != '_' && c != '-')
                {
                    throw new ArgumentException(
                        $"Provider name '{providerName}' contains invalid characters. Allowed: ASCII letters, digits, '.', '_', '-'.",
                        nameof(providerName));
                }
            }
        }

        private void EnsureDirectoryExists() => CredentialsDirectory.Ensure(_credentialsDirectory);

        private async Task<Dictionary<string, string>> LoadSelectionsAsync()
        {
            if (!File.Exists(_selectionFile))
            {
                return [];
            }

            try
            {
                var content = await File.ReadAllTextAsync(_selectionFile).ConfigureAwait(false);
                return JsonSerializer.Deserialize<Dictionary<string, string>>(content, _jsonOptions) ??
                       [];
            }
            catch (JsonException)
            {
                return [];
            }
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

using System.Runtime.Versioning;
using System.Text;

using NextIteration.SpectreConsole.Auth.Commands;

using static NextIteration.SpectreConsole.Auth.Persistence.Keychain.KeychainInterop;

namespace NextIteration.SpectreConsole.Auth.Persistence.Keychain
{
    /// <summary>
    /// <see cref="ICredentialManager"/> implementation backed by the macOS
    /// Keychain. Each stored credential becomes a generic-password item whose
    /// data blob carries the JSON payload and whose attributes carry the
    /// human-readable metadata (account name, environment, created-at).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This backend is marked <b>experimental</b>. P/Invoke against
    /// Security.framework is gnarly and the implementation has been exercised
    /// against a narrow set of macOS releases. Validate in your own environment
    /// before depending on it.
    /// </para>
    /// <para>
    /// The consumer-supplied <c>appIdentifier</c> is prefixed onto every
    /// <c>kSecAttrService</c> value so items from different CLIs don't collide
    /// in the same login keychain. Use a reverse-DNS style string like
    /// <c>com.mycompany.my-cli</c>.
    /// </para>
    /// </remarks>
    [SupportedOSPlatform("macos")]
    public sealed class KeychainCredentialManager : ICredentialManager
    {
        // Service name is "{appIdentifier}.{providerName}" so we can enumerate
        // all credentials for a provider by querying that service. Selection
        // records use the special service "{appIdentifier}.__selections__".
        private const string SelectionsServiceSuffix = ".__selections__";

        private readonly string _appIdentifier;
        private readonly Dictionary<string, ICredentialSummaryProvider> _summaryProviders;

        /// <summary>
        /// Constructs the manager. <paramref name="appIdentifier"/> isolates
        /// this CLI's keychain items from those of other apps on the same login
        /// keychain (e.g. <c>com.mycompany.my-cli</c>).
        /// </summary>
        public KeychainCredentialManager(
            string appIdentifier,
            IEnumerable<ICredentialSummaryProvider>? summaryProviders = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(appIdentifier);
            if (!OperatingSystem.IsMacOS())
            {
                throw new PlatformNotSupportedException("KeychainCredentialManager is only available on macOS.");
            }

            _appIdentifier = appIdentifier;
            _summaryProviders = (summaryProviders ?? [])
                .ToDictionary(p => p.ProviderName, StringComparer.OrdinalIgnoreCase);
        }

        /// <inheritdoc />
        public Task<string> AddCredentialAsync(string providerName, string accountName, string environment, string credentialData)
        {
            ValidateProviderName(providerName);
            var accountId = Guid.NewGuid().ToString();

            var attrs = new KeychainItem
            {
                Service = ServiceFor(providerName),
                Account = accountId,
                Label = accountName,
                Description = environment,
                Data = Encoding.UTF8.GetBytes(credentialData),
                OwnerAppIdentifier = _appIdentifier,
            };

            AddItem(attrs);

            // SecItemAdd can lag SecItemCopyMatching visibility under concurrent
            // keychain access, so a caller doing add-then-select/delete — e.g.
            // `accounts add` offering to activate the new credential — can race
            // the item's own appearance and see the follow-up lookup miss it.
            // Confirm the item is queryable before returning so that can't happen.
            ConfirmItemVisible(attrs.Service, accountId);

            return Task.FromResult(accountId);
        }

        /// <summary>
        /// Polls for a just-added item to become visible to
        /// <c>SecItemCopyMatching</c>, closing the brief add-visibility window.
        /// Best-effort: returns after a bounded wait even if the item never
        /// appears, leaving any genuine failure to the caller's own lookup.
        /// </summary>
        private void ConfirmItemVisible(string service, string account)
        {
            const int maxAttempts = 20;
            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                if (QuerySingleItem(service, account, includeData: false) is not null)
                {
                    return;
                }

                if (attempt < maxAttempts)
                {
                    Thread.Sleep(25);
                }
            }
        }

        /// <inheritdoc />
        public Task<IEnumerable<CredentialSummary>> ListCredentialsAsync(string providerName)
        {
            ValidateProviderName(providerName);
            providerName = ResolveStoredProviderName(providerName);
            var service = ServiceFor(providerName);
            _summaryProviders.TryGetValue(providerName, out var summaryProvider);

            var selectedId = ReadSelection(providerName);
            var items = QueryItems(service, includeData: summaryProvider is not null);

            var result = items
                .Select(i => new CredentialSummary
                {
                    AccountId = i.Account ?? string.Empty,
                    AccountName = i.Label ?? string.Empty,
                    ProviderName = providerName,
                    Environment = i.Description ?? string.Empty,
                    CreatedAt = i.CreatedAt ?? DateTime.MinValue,
                    IsSelected = selectedId is not null && string.Equals(selectedId, i.Account, StringComparison.OrdinalIgnoreCase),
                    DisplayFields = summaryProvider is not null && i.Data is not null
                        ? summaryProvider.GetDisplayFields(Encoding.UTF8.GetString(i.Data))
                        : [],

                    // False only when the data was actually asked for and did not
                    // arrive, matching the file backend's meaning of the flag: with
                    // no summary provider registered nothing is loaded, so there is
                    // nothing to report.
                    IsDecryptable = summaryProvider is null || i.Data is not null,
                })
                .OrderBy(c => c.AccountName)
                .ToList();

            return Task.FromResult<IEnumerable<CredentialSummary>>(result);
        }

        /// <inheritdoc />
        public Task<bool> DeleteCredentialAsync(string accountId)
        {
            if (!IsValidAccountId(accountId))
            {
                return Task.FromResult(false);
            }

            var match = FindItemByAccountId(accountId);
            if (match is null)
            {
                return Task.FromResult(false);
            }

            DeleteItem(match.Value.Service, match.Value.Account!);

            // Clear the selection record if it pointed at this credential.
            var providerName = ProviderNameFromService(match.Value.Service);
            if (providerName is not null)
            {
                var selected = ReadSelection(providerName);
                if (string.Equals(selected, accountId, StringComparison.OrdinalIgnoreCase))
                {
                    DeleteSelection(providerName);
                }
            }

            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public Task<bool> SelectCredentialAsync(string accountId)
        {
            if (!IsValidAccountId(accountId))
            {
                return Task.FromResult(false);
            }

            var match = FindItemByAccountId(accountId);
            if (match is null)
            {
                return Task.FromResult(false);
            }

            var providerName = ProviderNameFromService(match.Value.Service);
            if (providerName is null)
            {
                return Task.FromResult(false);
            }

            WriteSelection(providerName, accountId);
            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public Task<string?> GetSelectedCredentialAsync(string providerName)
        {
            ValidateProviderName(providerName);
            providerName = ResolveStoredProviderName(providerName);
            var selectedId = ReadSelection(providerName);
            if (selectedId is null)
            {
                return Task.FromResult<string?>(null);
            }

            return Task.FromResult(ReadItemDataById(providerName, selectedId));
        }

        /// <inheritdoc />
        public Task<string?> GetCredentialByIdAsync(string providerName, string accountId)
        {
            ValidateProviderName(providerName);
            providerName = ResolveStoredProviderName(providerName);
            ValidateAccountId(accountId);

            return Task.FromResult(ReadItemDataById(providerName, accountId));
        }

        /// <summary>
        /// Loads a generic-password Keychain item's <c>kSecValueData</c> for
        /// the given provider and account id. Returns <see langword="null"/>
        /// when the item doesn't exist or has no payload. Shared by
        /// <see cref="GetSelectedCredentialAsync"/> and
        /// <see cref="GetCredentialByIdAsync"/> — neither touches the
        /// selection record.
        /// </summary>
        private string? ReadItemDataById(string providerName, string accountId)
        {
            var service = ServiceFor(providerName);
            var item = QuerySingleItem(service, accountId, includeData: true);
            if (item is null || item.Data is null)
            {
                return null;
            }

            return Encoding.UTF8.GetString(item.Data);
        }

        /// <inheritdoc />
        public Task<IEnumerable<string>> GetProviderNamesAsync()
        {
            // Query every generic-password item owned by this app and distinct
            // the provider portion out of the service string.
            var items = QueryAllItemsForApp(includeData: false);
            var providerPrefix = _appIdentifier + ".";
            var names = items
                .Select(i => i.Service)
                .Where(s => s.StartsWith(providerPrefix, StringComparison.Ordinal) && !s.EndsWith(SelectionsServiceSuffix, StringComparison.Ordinal))
                .Select(s => s[providerPrefix.Length..])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();

            return Task.FromResult<IEnumerable<string>>(names);
        }

        /// <inheritdoc />
        public Task<IReadOnlyList<CredentialExport>> ExportCredentialsAsync()
        {
            var items = QueryAllItemsForApp(includeData: true);
            var selectionCache = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

            // Only real credential items are exported: skip the selection records,
            // and any item whose service/account doesn't resolve to a credential.
            var credentialItems = items.Where(i =>
                !i.Service.EndsWith(SelectionsServiceSuffix, StringComparison.Ordinal)
                && i.Account is not null
                && ProviderNameFromService(i.Service) is not null);

            var exports = new List<CredentialExport>();
            foreach (var item in credentialItems)
            {
                var providerName = ProviderNameFromService(item.Service)!;

                if (item.Data is null)
                {
                    // Requested but absent. Reachable only when the item was removed
                    // between enumeration and read: QuerySingleItem returns null solely
                    // for errSecItemNotFound, and every other status goes through
                    // ThrowIfError. A locked keychain or a denied read
                    // (errSecInteractionNotAllowed, errSecAuthFailed) therefore still
                    // aborts the whole export rather than skipping one item.
                    //
                    // Skip it. CredentialData flows straight into the archive, so an
                    // empty payload would write a valid-looking credential holding
                    // nothing, and the next import would restore that over a real
                    // secret. The caller reports the skipped count.
                    //
                    // Checked before the selection lookup so a skipped item costs no
                    // keychain round-trip.
                    continue;
                }

                if (!selectionCache.TryGetValue(providerName, out var selectedId))
                {
                    selectedId = ReadSelection(providerName);
                    selectionCache[providerName] = selectedId;
                }

                exports.Add(new CredentialExport
                {
                    AccountId = item.Account!, // non-null: guaranteed by the Where filter above
                    AccountName = item.Label ?? string.Empty,
                    ProviderName = providerName,
                    Environment = item.Description ?? string.Empty,
                    CredentialData = Encoding.UTF8.GetString(item.Data),
                    CreatedAt = item.CreatedAt ?? DateTime.MinValue,
                    IsSelected = selectedId is not null && string.Equals(selectedId, item.Account, StringComparison.OrdinalIgnoreCase),
                });
            }

            return Task.FromResult<IReadOnlyList<CredentialExport>>(exports);
        }

        /// <inheritdoc />
        public Task RestoreCredentialAsync(CredentialExport credential)
        {
            ArgumentNullException.ThrowIfNull(credential);
            ValidateProviderName(credential.ProviderName);
            ValidateAccountId(credential.AccountId);

            var service = ServiceFor(credential.ProviderName);

            // Replace any existing item with the same service + account id so a
            // re-import is idempotent. Keychain has no atomic upsert, so delete
            // then add — the creation date is reassigned by macOS regardless, so
            // CreatedAt is intentionally not carried across.
            var existing = QuerySingleItem(service, credential.AccountId, includeData: false);
            if (existing is not null)
            {
                DeleteItem(service, credential.AccountId);
            }

            AddItem(new KeychainItem
            {
                Service = service,
                Account = credential.AccountId,
                Label = credential.AccountName,
                Description = credential.Environment,
                Data = Encoding.UTF8.GetBytes(credential.CredentialData),
                OwnerAppIdentifier = _appIdentifier,
            });

            if (credential.IsSelected)
            {
                WriteSelection(credential.ProviderName, credential.AccountId);
            }

            return Task.CompletedTask;
        }

        // =========================
        // Internal helpers
        // =========================

        /// <summary>
        /// Maps a caller-supplied provider name onto the spelling this store actually
        /// used, so lookups match case-insensitively like the file backend's do.
        /// </summary>
        /// <remarks>
        /// Resolution rather than normalisation is deliberate. The provider name is part
        /// of this backend's storage key, so lowercasing the key would orphan every item
        /// already stored under a mixed-case spelling. Resolving instead leaves the stored
        /// format untouched: the caller's spelling is matched against what is on disk and
        /// the stored spelling is used for the query. Falls back to the caller's spelling
        /// when nothing matches, so a genuine miss still behaves as a miss (#49).
        /// </remarks>
        private string ResolveStoredProviderName(string providerName)
        {
            var providerPrefix = _appIdentifier + ".";
            foreach (var item in QueryAllItemsForApp(includeData: false))
            {
                if (!item.Service.StartsWith(providerPrefix, StringComparison.Ordinal) ||
                    item.Service.EndsWith(SelectionsServiceSuffix, StringComparison.Ordinal))
                {
                    continue;
                }

                var stored = item.Service[providerPrefix.Length..];
                if (stored.Equals(providerName, StringComparison.OrdinalIgnoreCase))
                {
                    return stored;
                }
            }

            return providerName;
        }

        /// <summary>
        /// Whether <paramref name="item"/> belongs to this manager's app.
        /// </summary>
        /// <remarks>
        /// Items written by this version carry the owning app identifier in
        /// <c>kSecAttrGeneric</c> and are matched on it exactly. Items written before that
        /// attribute existed carry nothing, so they fall back to the old service-prefix
        /// check — without which every previously stored credential would vanish.
        /// <para>
        /// The fallback is not a complete fix and is not presented as one: a legacy item
        /// belonging to an app whose identifier is a dot-prefix of another's stays
        /// ambiguous until it is rewritten. Everything written from now on is scoped
        /// exactly (#55).
        /// </para>
        /// </remarks>
        private bool IsOwnedByThisApp(KeychainItem item)
        {
            if (!string.IsNullOrEmpty(item.OwnerAppIdentifier))
            {
                return string.Equals(item.OwnerAppIdentifier, _appIdentifier, StringComparison.Ordinal);
            }

            // Legacy item: no owner recorded, so fall back to the ambiguous prefix test.
            return item.Service.StartsWith(_appIdentifier + ".", StringComparison.Ordinal)
                || string.Equals(item.Service, SelectionsService, StringComparison.Ordinal);
        }

        private string ServiceFor(string providerName) => $"{_appIdentifier}.{providerName}";

        private string SelectionsService => $"{_appIdentifier}{SelectionsServiceSuffix}";

        private string? ProviderNameFromService(string service)
        {
            var prefix = _appIdentifier + ".";
            if (!service.StartsWith(prefix, StringComparison.Ordinal))
            {
                return null;
            }

            var candidate = service[prefix.Length..];
            return candidate == SelectionsServiceSuffix.TrimStart('.') ? null : candidate;
        }

        private string? ReadSelection(string providerName)
        {
            var item = QuerySingleItem(SelectionsService, providerName, includeData: true);
            if (item?.Data is null)
            {
                return null;
            }

            return Encoding.UTF8.GetString(item.Data);
        }

        private void WriteSelection(string providerName, string accountId)
        {
            var existing = QuerySingleItem(SelectionsService, providerName, includeData: false);
            var bytes = Encoding.UTF8.GetBytes(accountId);
            if (existing is null)
            {
                AddItem(new KeychainItem
                {
                    Service = SelectionsService,
                    Account = providerName,
                    Label = $"{_appIdentifier} active credential ({providerName})",
                    Description = string.Empty,
                    Data = bytes,
                    OwnerAppIdentifier = _appIdentifier,
                });
            }
            else
            {
                UpdateItemData(SelectionsService, providerName, bytes);
            }
        }

        private void DeleteSelection(string providerName) => DeleteItem(SelectionsService, providerName);

        private (string Service, string? Account)? FindItemByAccountId(string accountId)
        {
            // Enumerate all app-owned items; pick the one whose account matches.
            // Keychain doesn't index on account alone across services, so this
            // is a linear scan — acceptable because credential counts are tiny.
            var match = QueryAllItemsForApp(includeData: false)
                .FirstOrDefault(item =>
                    string.Equals(item.Account, accountId, StringComparison.OrdinalIgnoreCase)
                    && !item.Service.EndsWith(SelectionsServiceSuffix, StringComparison.Ordinal));

            return match is null ? null : (match.Service, match.Account);
        }

        // =========================
        // Provider-name validation — mirrors FileCredentialManager rules so the
        // two backends accept the same set of names.
        // =========================

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

        private static bool IsValidAccountId(string? accountId) =>
            !string.IsNullOrWhiteSpace(accountId) && Guid.TryParse(accountId, out _);

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

        // =========================
        // Keychain operations — each takes ownership of every CF object it
        // creates and releases in finally.
        // =========================

        private sealed class KeychainItem
        {
            public required string Service { get; init; }
            public string? Account { get; init; }
            public string? Label { get; init; }
            public string? Description { get; init; }
            public DateTime? CreatedAt { get; init; }
            public byte[]? Data { get; init; }

            /// <summary>
            /// Owning app identifier, stored in <c>kSecAttrComment</c>. Null for items
            /// written before this attribute existed — see <see cref="IsOwnedByThisApp"/>.
            /// </summary>
            public string? OwnerAppIdentifier { get; init; }
        }

        private static void AddItem(KeychainItem item)
        {
            var handles = new List<IntPtr>();
            try
            {
                var serviceCf = Track(handles, NewCfString(item.Service));
                var accountCf = Track(handles, NewCfString(item.Account ?? string.Empty));
                var labelCf = Track(handles, NewCfString(item.Label ?? string.Empty));
                var descCf = Track(handles, NewCfString(item.Description ?? string.Empty));
                var dataCf = Track(handles, NewCfData(item.Data ?? []));

                // kSecAttrComment records which app owns the item, so scoping does not have
                // to be inferred from the service string. That inference was ambiguous:
                // the service is "{app}.{provider}" and provider names may contain dots, so
                // app "com.acme.cli" could not tell its own "pro.Adobe" item from app
                // "com.acme.cli.pro"'s "Adobe" item (#55).
                var ownerCf = Track(handles, NewCfString(item.OwnerAppIdentifier ?? string.Empty));

                var pairs = new List<(IntPtr, IntPtr)>
                {
                    (Constants.KSecClass, Constants.KSecClassGenericPassword),
                    (Constants.KSecAttrService, serviceCf),
                    (Constants.KSecAttrAccount, accountCf),
                    (Constants.KSecAttrLabel, labelCf),
                    (Constants.KSecAttrDescription, descCf),
                    (Constants.KSecAttrComment, ownerCf),
                    (Constants.KSecValueData, dataCf),
                };

                var query = Track(handles, NewCfDictionary(pairs));

                var status = SecItemAdd(query, out _);
                ThrowIfError(status, "SecItemAdd");
            }
            finally
            {
                ReleaseAll(handles);
            }
        }

        private static void UpdateItemData(string service, string account, byte[] data)
        {
            var handles = new List<IntPtr>();
            try
            {
                var serviceCf = Track(handles, NewCfString(service));
                var accountCf = Track(handles, NewCfString(account));
                var query = Track(handles, NewCfDictionary(
                [
                    (Constants.KSecClass, Constants.KSecClassGenericPassword),
                    (Constants.KSecAttrService, serviceCf),
                    (Constants.KSecAttrAccount, accountCf),
                ]));

                var dataCf = Track(handles, NewCfData(data));
                var updateAttrs = Track(handles, NewCfDictionary(
                [
                    (Constants.KSecValueData, dataCf),
                ]));

                var status = SecItemUpdate(query, updateAttrs);
                ThrowIfError(status, "SecItemUpdate");
            }
            finally
            {
                ReleaseAll(handles);
            }
        }

        private static void DeleteItem(string service, string account)
        {
            var handles = new List<IntPtr>();
            try
            {
                var serviceCf = Track(handles, NewCfString(service));
                var accountCf = Track(handles, NewCfString(account));
                var query = Track(handles, NewCfDictionary(
                [
                    (Constants.KSecClass, Constants.KSecClassGenericPassword),
                    (Constants.KSecAttrService, serviceCf),
                    (Constants.KSecAttrAccount, accountCf),
                ]));

                var status = SecItemDelete(query);
                if (status == ErrSecItemNotFound)
                {
                    return;
                }

                ThrowIfError(status, "SecItemDelete");
            }
            finally
            {
                ReleaseAll(handles);
            }
        }

        /// <summary>
        /// Fetches one item by service + account, or null if it does not exist or is not
        /// ours. See <see cref="IsOwnedByThisApp"/> — an exact service query is not on its
        /// own proof of ownership, because the service string is ambiguous (#55).
        /// </summary>
        private KeychainItem? QuerySingleItem(string service, string account, bool includeData)
        {
            var handles = new List<IntPtr>();
            try
            {
                var serviceCf = Track(handles, NewCfString(service));
                var accountCf = Track(handles, NewCfString(account));
                var query = Track(handles, NewCfDictionary(
                [
                    (Constants.KSecClass, Constants.KSecClassGenericPassword),
                    (Constants.KSecAttrService, serviceCf),
                    (Constants.KSecAttrAccount, accountCf),
                    (Constants.KSecMatchLimit, Constants.KSecMatchLimitOne),
                    (Constants.KSecReturnAttributes, Constants.KCFBooleanTrue),
                    (Constants.KSecReturnData, includeData ? Constants.KCFBooleanTrue : IntPtr.Zero),
                ]));

                var status = SecItemCopyMatching(query, out var result);
                if (status == ErrSecItemNotFound)
                {
                    return null;
                }

                ThrowIfError(status, "SecItemCopyMatching");

                try
                {
                    var decoded = DecodeItem(result);

                    // Present but owned by another app: treat as not found rather than
                    // handing back someone else's credential (#55).
                    return decoded is not null && IsOwnedByThisApp(decoded) ? decoded : null;
                }
                finally
                {
                    if (result != IntPtr.Zero)
                    {
                        CFRelease(result);
                    }
                }
            }
            finally
            {
                ReleaseAll(handles);
            }
        }

        private List<KeychainItem> QueryItems(string service, bool includeData)
        {
            // Bulk query: request attributes only. Combining kSecReturnAttributes
            // + kSecReturnData + kSecMatchLimitAll in a single SecItemCopyMatching
            // call fails with errSecParam (-50) on macOS — Security.framework only
            // supports that combination with kSecMatchLimitOne. When data is
            // needed, we do a per-item follow-up below.
            List<KeychainItem> stubs;
            var handles = new List<IntPtr>();
            try
            {
                var serviceCf = Track(handles, NewCfString(service));
                var query = Track(handles, NewCfDictionary(
                [
                    (Constants.KSecClass, Constants.KSecClassGenericPassword),
                    (Constants.KSecAttrService, serviceCf),
                    (Constants.KSecMatchLimit, Constants.KSecMatchLimitAll),
                    (Constants.KSecReturnAttributes, Constants.KCFBooleanTrue),
                ]));

                var status = SecItemCopyMatching(query, out var result);
                if (status == ErrSecItemNotFound)
                {
                    return [];
                }

                ThrowIfError(status, "SecItemCopyMatching");

                try
                {
                    // The service string alone does not establish ownership, so filter even
                    // though this query pinned an exact service (#55).
                    stubs = [.. DecodeArray(result).Where(IsOwnedByThisApp)];
                }
                finally
                {
                    if (result != IntPtr.Zero)
                    {
                        CFRelease(result);
                    }
                }
            }
            finally
            {
                ReleaseAll(handles);
            }

            if (!includeData)
            {
                return stubs;
            }

            // Data round-trip: per-item QuerySingleItem(includeData: true) uses
            // kSecMatchLimitOne which supports attributes+data in one call.
            var withData = new List<KeychainItem>(stubs.Count);
            foreach (var stub in stubs)
            {
                if (stub.Account is null)
                {
                    withData.Add(stub);
                    continue;
                }

                var full = QuerySingleItem(stub.Service, stub.Account, includeData: true);
                // If the item vanished between queries (theoretically possible
                // under concurrent modification), fall back to the attribute-only
                // stub rather than dropping it.
                withData.Add(full ?? stub);
            }
            return withData;
        }

        private List<KeychainItem> QueryAllItemsForApp(bool includeData)
        {
            // No per-service filter — just pull everything, then filter in-memory
            // to items whose service starts with our appIdentifier. Keychain
            // queries require *some* filter so we fall back to class-only and
            // trust the prefix check.
            //
            // Like QueryItems above, we fetch attributes only here; if data is
            // requested, a per-item follow-up runs on the filtered set.
            List<KeychainItem> stubs;
            var handles = new List<IntPtr>();
            try
            {
                var query = Track(handles, NewCfDictionary(
                [
                    (Constants.KSecClass, Constants.KSecClassGenericPassword),
                    (Constants.KSecMatchLimit, Constants.KSecMatchLimitAll),
                    (Constants.KSecReturnAttributes, Constants.KCFBooleanTrue),
                ]));

                var status = SecItemCopyMatching(query, out var result);
                if (status == ErrSecItemNotFound)
                {
                    return [];
                }

                ThrowIfError(status, "SecItemCopyMatching");

                try
                {
                    var items = DecodeArray(result);
                    stubs = [.. items.Where(IsOwnedByThisApp)];
                }
                finally
                {
                    if (result != IntPtr.Zero)
                    {
                        CFRelease(result);
                    }
                }
            }
            finally
            {
                ReleaseAll(handles);
            }

            if (!includeData)
            {
                return stubs;
            }

            var withData = new List<KeychainItem>(stubs.Count);
            foreach (var stub in stubs)
            {
                if (stub.Account is null)
                {
                    withData.Add(stub);
                    continue;
                }
                var full = QuerySingleItem(stub.Service, stub.Account, includeData: true);
                withData.Add(full ?? stub);
            }
            return withData;
        }

        // =========================
        // Decoding CF results
        // =========================

        private static List<KeychainItem> DecodeArray(IntPtr arrayOrDict)
        {
            if (arrayOrDict == IntPtr.Zero)
            {
                return [];
            }

            // The result can be either a CFArray (match-limit-all, multiple items)
            // or a single CFDictionary (match-limit-all + one result, or an older
            // macOS quirk). Dispatch on CF type ID — probing a CFArray with
            // CFDictionaryGetValue toll-free-bridges to [NSArray objectForKey:]
            // which crashes the process.
            var typeId = CFGetTypeID(arrayOrDict);
            if (typeId == CFDictionaryGetTypeID())
            {
                var single = DecodeItem(arrayOrDict);
                return single is null ? [] : [single];
            }

            if (typeId != CFArrayGetTypeID())
            {
                // Unknown result type — safe fallback: treat as no results.
                return [];
            }

            var count = CFArrayGetCount(arrayOrDict);
            var results = new List<KeychainItem>((int)count);
            for (long i = 0; i < count; i++)
            {
                var dict = CFArrayGetValueAtIndex(arrayOrDict, i);
                var item = DecodeItem(dict);
                if (item is not null)
                {
                    results.Add(item);
                }
            }
            return results;
        }

        private static KeychainItem? DecodeItem(IntPtr dict)
        {
            if (dict == IntPtr.Zero)
            {
                return null;
            }

            var service = ReadCfStringAt(dict, Constants.KSecAttrService);
            if (service is null)
            {
                return null;
            }

            return new KeychainItem
            {
                Service = service,
                Account = ReadCfStringAt(dict, Constants.KSecAttrAccount),
                Label = ReadCfStringAt(dict, Constants.KSecAttrLabel),
                Description = ReadCfStringAt(dict, Constants.KSecAttrDescription),
                CreatedAt = ReadCfDateAt(dict, Constants.KSecAttrCreationDate),
                Data = ReadCfDataAt(dict, Constants.KSecValueData),
                OwnerAppIdentifier = ReadCfStringAt(dict, Constants.KSecAttrComment),
            };
        }

        private static string? ReadCfStringAt(IntPtr dict, IntPtr key)
        {
            var value = CFDictionaryGetValue(dict, key);
            return value == IntPtr.Zero ? null : ReadCfString(value);
        }

        private static byte[]? ReadCfDataAt(IntPtr dict, IntPtr key)
        {
            var value = CFDictionaryGetValue(dict, key);
            return value == IntPtr.Zero ? null : ReadCfData(value);
        }

        private static DateTime? ReadCfDateAt(IntPtr dict, IntPtr key)
        {
            var value = CFDictionaryGetValue(dict, key);
            return value == IntPtr.Zero ? null : ReadCfDate(value);
        }

        // =========================
        // Error handling + handle tracking
        // =========================

        private static IntPtr Track(List<IntPtr> handles, IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                handles.Add(handle);
            }

            return handle;
        }

        private static void ReleaseAll(List<IntPtr> handles)
        {
            foreach (var h in handles)
            {
                CFRelease(h);
            }
        }

        private static void ThrowIfError(int status, string operation)
        {
            if (status == ErrSecSuccess)
            {
                return;
            }

            if (status == ErrSecUserCanceled)
            {
                throw new InvalidOperationException($"{operation}: user cancelled the keychain prompt.");
            }
            throw new InvalidOperationException($"{operation} failed: OSStatus {status}.");
        }
    }
}

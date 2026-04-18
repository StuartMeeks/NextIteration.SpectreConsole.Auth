using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

using NextIteration.SpectreConsole.Auth.Commands;

using static NextIteration.SpectreConsole.Auth.Persistence.Keychain.KeychainInterop;

namespace NextIteration.SpectreConsole.Auth.Persistence.Keychain;

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
        };

        AddItem(attrs);
        return Task.FromResult(accountId);
    }

    /// <inheritdoc />
    public Task<IEnumerable<CredentialSummary>> ListCredentialsAsync(string providerName)
    {
        ValidateProviderName(providerName);
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
            })
            .OrderBy(c => c.AccountName)
            .ToList();

        return Task.FromResult<IEnumerable<CredentialSummary>>(result);
    }

    /// <inheritdoc />
    public Task<bool> DeleteCredentialAsync(string accountId)
    {
        var match = FindItemByAccountId(accountId);
        if (match is null)
            return Task.FromResult(false);

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
        var match = FindItemByAccountId(accountId);
        if (match is null)
            return Task.FromResult(false);

        var providerName = ProviderNameFromService(match.Value.Service);
        if (providerName is null)
            return Task.FromResult(false);

        WriteSelection(providerName, accountId);
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public Task<string?> GetSelectedCredentialAsync(string providerName)
    {
        ValidateProviderName(providerName);
        var selectedId = ReadSelection(providerName);
        if (selectedId is null)
            return Task.FromResult<string?>(null);

        return Task.FromResult(ReadItemDataById(providerName, selectedId));
    }

    /// <inheritdoc />
    public Task<string?> GetCredentialByIdAsync(string providerName, string accountId)
    {
        ValidateProviderName(providerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountId);

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
        if (item is null || item.Data is null) return null;
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

    // =========================
    // Internal helpers
    // =========================

    private string ServiceFor(string providerName) => $"{_appIdentifier}.{providerName}";

    private string SelectionsService => $"{_appIdentifier}{SelectionsServiceSuffix}";

    private string? ProviderNameFromService(string service)
    {
        var prefix = _appIdentifier + ".";
        if (!service.StartsWith(prefix, StringComparison.Ordinal)) return null;
        var candidate = service[prefix.Length..];
        return candidate == SelectionsServiceSuffix.TrimStart('.') ? null : candidate;
    }

    private string? ReadSelection(string providerName)
    {
        var item = QuerySingleItem(SelectionsService, providerName, includeData: true);
        if (item?.Data is null) return null;
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
            });
        }
        else
        {
            UpdateItemData(SelectionsService, providerName, bytes);
        }
    }

    private void DeleteSelection(string providerName)
    {
        DeleteItem(SelectionsService, providerName);
    }

    private (string Service, string? Account)? FindItemByAccountId(string accountId)
    {
        // Enumerate all app-owned items; pick the one whose account matches.
        // Keychain doesn't index on account alone across services, so this
        // is a linear scan — acceptable because credential counts are tiny.
        var items = QueryAllItemsForApp(includeData: false);
        foreach (var item in items)
        {
            if (string.Equals(item.Account, accountId, StringComparison.OrdinalIgnoreCase)
                && !item.Service.EndsWith(SelectionsServiceSuffix, StringComparison.Ordinal))
            {
                return (item.Service, item.Account);
            }
        }
        return null;
    }

    // =========================
    // Provider-name validation — mirrors FileCredentialManager rules so the
    // two backends accept the same set of names.
    // =========================

    private static void ValidateProviderName(string providerName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
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

            var pairs = new List<(IntPtr, IntPtr)>
            {
                (Constants.KSecClass, Constants.KSecClassGenericPassword),
                (Constants.KSecAttrService, serviceCf),
                (Constants.KSecAttrAccount, accountCf),
                (Constants.KSecAttrLabel, labelCf),
                (Constants.KSecAttrDescription, descCf),
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
            if (status == ErrSecItemNotFound) return;
            ThrowIfError(status, "SecItemDelete");
        }
        finally
        {
            ReleaseAll(handles);
        }
    }

    private static KeychainItem? QuerySingleItem(string service, string account, bool includeData)
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
            if (status == ErrSecItemNotFound) return null;
            ThrowIfError(status, "SecItemCopyMatching");

            try
            {
                return DecodeItem(result);
            }
            finally
            {
                if (result != IntPtr.Zero) CFRelease(result);
            }
        }
        finally
        {
            ReleaseAll(handles);
        }
    }

    private static List<KeychainItem> QueryItems(string service, bool includeData)
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
            if (status == ErrSecItemNotFound) return [];
            ThrowIfError(status, "SecItemCopyMatching");

            try
            {
                stubs = DecodeArray(result);
            }
            finally
            {
                if (result != IntPtr.Zero) CFRelease(result);
            }
        }
        finally
        {
            ReleaseAll(handles);
        }

        if (!includeData) return stubs;

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
            if (status == ErrSecItemNotFound) return [];
            ThrowIfError(status, "SecItemCopyMatching");

            try
            {
                var items = DecodeArray(result);
                stubs = items
                    .Where(i => i.Service.StartsWith(_appIdentifier + ".", StringComparison.Ordinal)
                        || string.Equals(i.Service, SelectionsService, StringComparison.Ordinal))
                    .ToList();
            }
            finally
            {
                if (result != IntPtr.Zero) CFRelease(result);
            }
        }
        finally
        {
            ReleaseAll(handles);
        }

        if (!includeData) return stubs;

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
        if (arrayOrDict == IntPtr.Zero) return [];

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
            if (item is not null) results.Add(item);
        }
        return results;
    }

    private static KeychainItem? DecodeItem(IntPtr dict)
    {
        if (dict == IntPtr.Zero) return null;

        var service = ReadCfStringAt(dict, Constants.KSecAttrService);
        if (service is null) return null;

        return new KeychainItem
        {
            Service = service,
            Account = ReadCfStringAt(dict, Constants.KSecAttrAccount),
            Label = ReadCfStringAt(dict, Constants.KSecAttrLabel),
            Description = ReadCfStringAt(dict, Constants.KSecAttrDescription),
            CreatedAt = ReadCfDateAt(dict, Constants.KSecAttrCreationDate),
            Data = ReadCfDataAt(dict, Constants.KSecValueData),
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
        if (handle != IntPtr.Zero) handles.Add(handle);
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
        if (status == ErrSecSuccess) return;
        if (status == ErrSecUserCanceled)
        {
            throw new InvalidOperationException($"{operation}: user cancelled the keychain prompt.");
        }
        throw new InvalidOperationException($"{operation} failed: OSStatus {status}.");
    }
}

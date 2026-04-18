using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Commands;

using static NextIteration.SpectreConsole.Auth.Persistence.Libsecret.LibsecretInterop;

namespace NextIteration.SpectreConsole.Auth.Persistence.Libsecret;

/// <summary>
/// <see cref="ICredentialManager"/> implementation backed by the Secret
/// Service API (libsecret). Each credential becomes a libsecret item in
/// the user's default keyring (GNOME Keyring, KWallet's shim, etc.).
/// </summary>
/// <remarks>
/// <para>
/// This backend is marked <b>experimental</b>. Tested against
/// <c>gnome-keyring-daemon</c> on Ubuntu; behaviour on other Secret
/// Service implementations (KWallet, <c>kwallet-secrets</c>, or the
/// <c>pass</c> shim) has not been verified.
/// </para>
/// <para>
/// Requires a running Secret Service daemon. Headless containers and
/// SSH-only servers typically don't have one; calls will throw at the
/// first operation. Consumers building for unattended environments should
/// fall back to <see cref="FileCredentialManager"/>.
/// </para>
/// </remarks>
[SupportedOSPlatform("linux")]
public sealed class LibsecretCredentialManager : ICredentialManager
{
    // Attribute keys on each libsecret item — scoped under our app so
    // queries don't collide with other tools using the same keyring.
    private const string AttrApp = "nextIteration.sca.app";
    private const string AttrKind = "nextIteration.sca.kind";     // "credential" | "selection"
    private const string AttrProvider = "nextIteration.sca.provider";
    private const string AttrAccount = "nextIteration.sca.account";
    private const string AttrLabel = "nextIteration.sca.label";       // user-supplied account name
    private const string AttrEnvironment = "nextIteration.sca.environment";
    private const string AttrCreatedAt = "nextIteration.sca.createdAt"; // ISO-8601 UTC

    private const string KindCredential = "credential";
    private const string KindSelection = "selection";

    private readonly string _appIdentifier;
    private readonly string _collection;
    private readonly Dictionary<string, ICredentialSummaryProvider> _summaryProviders;

    /// <summary>
    /// Constructs the manager. <paramref name="appIdentifier"/> scopes this
    /// CLI's items in the keyring so they don't collide with other tools
    /// using the same keyring (e.g. <c>com.mycompany.my-cli</c>).
    /// <paramref name="collection"/> selects the Secret Service collection
    /// that new items are written to; defaults to <c>"default"</c> (usually
    /// the login keyring). Pass <c>"session"</c> to target the in-memory
    /// session collection, which always exists on a running daemon.
    /// </summary>
    public LibsecretCredentialManager(
        string appIdentifier,
        IEnumerable<ICredentialSummaryProvider>? summaryProviders = null,
        string collection = "default")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appIdentifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(collection);
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("LibsecretCredentialManager is only available on Linux.");
        }

        _appIdentifier = appIdentifier;
        _collection = collection;
        _summaryProviders = (summaryProviders ?? [])
            .ToDictionary(p => p.ProviderName, StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public Task<string> AddCredentialAsync(string providerName, string accountName, string environment, string credentialData)
    {
        ValidateProviderName(providerName);
        var accountId = Guid.NewGuid().ToString();

        var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AttrApp] = _appIdentifier,
            [AttrKind] = KindCredential,
            [AttrProvider] = providerName,
            [AttrAccount] = accountId,
            [AttrLabel] = accountName,
            [AttrEnvironment] = environment,
            [AttrCreatedAt] = DateTime.UtcNow.ToString("O"),
        };
        var label = $"{_appIdentifier}: {providerName}/{accountName}";

        StoreItem(attrs, label, credentialData);
        return Task.FromResult(accountId);
    }

    /// <inheritdoc />
    public Task<IEnumerable<CredentialSummary>> ListCredentialsAsync(string providerName)
    {
        ValidateProviderName(providerName);
        _summaryProviders.TryGetValue(providerName, out var summaryProvider);

        var selectedId = ReadSelection(providerName);
        var items = SearchItems(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindCredential,
                [AttrProvider] = providerName,
            },
            loadSecrets: summaryProvider is not null);

        var result = items
            .Select(i => new CredentialSummary
            {
                AccountId = i.Attributes.GetValueOrDefault(AttrAccount, string.Empty),
                AccountName = i.Attributes.GetValueOrDefault(AttrLabel, string.Empty),
                ProviderName = providerName,
                Environment = i.Attributes.GetValueOrDefault(AttrEnvironment, string.Empty),
                CreatedAt = ParseCreatedAt(i.Attributes.GetValueOrDefault(AttrCreatedAt)),
                IsSelected = selectedId is not null && string.Equals(
                    selectedId, i.Attributes.GetValueOrDefault(AttrAccount), StringComparison.OrdinalIgnoreCase),
                DisplayFields = summaryProvider is not null && i.Secret is not null
                    ? summaryProvider.GetDisplayFields(i.Secret)
                    : [],
            })
            .OrderBy(c => c.AccountName)
            .ToList();

        return Task.FromResult<IEnumerable<CredentialSummary>>(result);
    }

    /// <inheritdoc />
    public Task<bool> DeleteCredentialAsync(string accountId)
    {
        // Find the item so we know its provider (for selection cleanup).
        var match = SearchItems(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindCredential,
                [AttrAccount] = accountId,
            },
            loadSecrets: false).FirstOrDefault();

        if (match is null) return Task.FromResult(false);

        ClearItem(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AttrApp] = _appIdentifier,
            [AttrKind] = KindCredential,
            [AttrAccount] = accountId,
        });

        var providerName = match.Attributes.GetValueOrDefault(AttrProvider);
        if (providerName is not null)
        {
            var selected = ReadSelection(providerName);
            if (string.Equals(selected, accountId, StringComparison.OrdinalIgnoreCase))
            {
                ClearSelection(providerName);
            }
        }

        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public Task<bool> SelectCredentialAsync(string accountId)
    {
        var match = SearchItems(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindCredential,
                [AttrAccount] = accountId,
            },
            loadSecrets: false).FirstOrDefault();

        if (match is null) return Task.FromResult(false);

        var providerName = match.Attributes.GetValueOrDefault(AttrProvider);
        if (providerName is null) return Task.FromResult(false);

        WriteSelection(providerName, accountId);
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public Task<string?> GetSelectedCredentialAsync(string providerName)
    {
        ValidateProviderName(providerName);
        var selectedId = ReadSelection(providerName);
        if (selectedId is null) return Task.FromResult<string?>(null);

        return Task.FromResult(LookupCredentialByAccountId(providerName, selectedId));
    }

    /// <inheritdoc />
    public Task<string?> GetCredentialByIdAsync(string providerName, string accountId)
    {
        ValidateProviderName(providerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(accountId);

        return Task.FromResult(LookupCredentialByAccountId(providerName, accountId));
    }

    /// <summary>
    /// Secret Service lookup keyed on <c>(app, kind=credential, provider,
    /// account)</c>. Shared by <see cref="GetSelectedCredentialAsync"/>
    /// and <see cref="GetCredentialByIdAsync"/> — neither modifies the
    /// selection record.
    /// </summary>
    private string? LookupCredentialByAccountId(string providerName, string accountId)
    {
        return LookupPassword(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AttrApp] = _appIdentifier,
            [AttrKind] = KindCredential,
            [AttrProvider] = providerName,
            [AttrAccount] = accountId,
        });
    }

    /// <inheritdoc />
    public Task<IEnumerable<string>> GetProviderNamesAsync()
    {
        var items = SearchItems(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindCredential,
            },
            loadSecrets: false);

        var names = items
            .Select(i => i.Attributes.GetValueOrDefault(AttrProvider))
            .Where(n => !string.IsNullOrEmpty(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        return Task.FromResult<IEnumerable<string>>(names!);
    }

    // =========================
    // Internal helpers
    // =========================

    private string? ReadSelection(string providerName)
    {
        return LookupPassword(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AttrApp] = _appIdentifier,
            [AttrKind] = KindSelection,
            [AttrProvider] = providerName,
        });
    }

    private void WriteSelection(string providerName, string accountId)
    {
        // store overwrites an existing item with matching attributes, so
        // we don't need a separate add-or-update dance.
        StoreItem(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindSelection,
                [AttrProvider] = providerName,
            },
            label: $"{_appIdentifier}: active {providerName}",
            password: accountId);
    }

    private void ClearSelection(string providerName)
    {
        ClearItem(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AttrApp] = _appIdentifier,
            [AttrKind] = KindSelection,
            [AttrProvider] = providerName,
        });
    }

    private static DateTime ParseCreatedAt(string? value)
    {
        if (string.IsNullOrEmpty(value)) return DateTime.MinValue;
        return DateTime.TryParse(
            value,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind,
            out var parsed)
            ? parsed
            : DateTime.MinValue;
    }

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
    // Secret Service operations — each takes ownership of every GHashTable
    // / GError handle it creates and releases them via try/finally.
    // =========================

    private sealed class StoredItem
    {
        public required Dictionary<string, string> Attributes { get; init; }
        public string? Secret { get; init; }
    }

    private void StoreItem(Dictionary<string, string> attributes, string label, string password)
    {
        var attrs = NewAttributes(attributes);
        try
        {
            var status = secret_password_storev_sync(
                IntPtr.Zero,
                attrs,
                _collection,
                label,
                password,
                IntPtr.Zero,
                out var error);
            ThrowIfGError(error, "secret_password_storev_sync");
            if (status == 0)
            {
                throw new InvalidOperationException("secret_password_storev_sync returned FALSE without a GError — the Secret Service may not be available.");
            }
        }
        finally
        {
            g_hash_table_unref(attrs);
        }
    }

    private static string? LookupPassword(Dictionary<string, string> attributes)
    {
        var attrs = NewAttributes(attributes);
        try
        {
            var result = secret_password_lookupv_sync(IntPtr.Zero, attrs, IntPtr.Zero, out var error);
            ThrowIfGError(error, "secret_password_lookupv_sync");
            if (result == IntPtr.Zero) return null;
            try
            {
                return ReadUtf8(result);
            }
            finally
            {
                secret_password_free(result);
            }
        }
        finally
        {
            g_hash_table_unref(attrs);
        }
    }

    private static void ClearItem(Dictionary<string, string> attributes)
    {
        var attrs = NewAttributes(attributes);
        try
        {
            _ = secret_password_clearv_sync(IntPtr.Zero, attrs, IntPtr.Zero, out var error);
            ThrowIfGError(error, "secret_password_clearv_sync");
        }
        finally
        {
            g_hash_table_unref(attrs);
        }
    }

    private static List<StoredItem> SearchItems(Dictionary<string, string> attributes, bool loadSecrets)
    {
        var attrs = NewAttributes(attributes);
        var flags = SecretSearchAll | (loadSecrets ? SecretSearchLoadSecrets | SecretSearchUnlock : 0);
        try
        {
            var listPtr = secret_password_searchv_sync(IntPtr.Zero, attrs, flags, IntPtr.Zero, out var error);
            ThrowIfGError(error, "secret_password_searchv_sync");

            var results = new List<StoredItem>();
            if (listPtr == IntPtr.Zero) return results;

            try
            {
                var count = g_list_length(listPtr);
                for (uint i = 0; i < count; i++)
                {
                    var retrievable = g_list_nth_data(listPtr, i);
                    if (retrievable == IntPtr.Zero) continue;

                    var itemAttrs = secret_retrievable_get_attributes(retrievable);
                    var managedAttrs = itemAttrs == IntPtr.Zero ? [] : ReadAttributes(itemAttrs);
                    if (itemAttrs != IntPtr.Zero) g_hash_table_unref(itemAttrs);

                    string? secret = null;
                    if (loadSecrets)
                    {
                        var secretValue = secret_retrievable_retrieve_secret_sync(retrievable, IntPtr.Zero, out var secretError);
                        ThrowIfGError(secretError, "secret_retrievable_retrieve_secret_sync");
                        try
                        {
                            secret = ReadSecretValueAsString(secretValue);
                        }
                        finally
                        {
                            if (secretValue != IntPtr.Zero) secret_value_unref(secretValue);
                        }
                    }

                    results.Add(new StoredItem
                    {
                        Attributes = managedAttrs,
                        Secret = secret,
                    });

                    // Each GList node owns a reference to its data; releasing
                    // the data item itself is the caller's job.
                    g_object_unref(retrievable);
                }
            }
            finally
            {
                g_list_free(listPtr);
            }
            return results;
        }
        finally
        {
            g_hash_table_unref(attrs);
        }
    }
}

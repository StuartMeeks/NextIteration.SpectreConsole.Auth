using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Commands;

using static NextIteration.SpectreConsole.Auth.Persistence.Libsecret.LibsecretInterop;

namespace NextIteration.SpectreConsole.Auth.Persistence.Libsecret
{
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

            // A just-stored Secret Service item isn't always immediately visible
            // to a follow-up search under concurrent access, so a caller doing
            // add-then-select/delete can race the item's appearance. Confirm it's
            // queryable before returning so that can't happen.
            ConfirmItemVisible(providerName, accountId);

            return Task.FromResult(accountId);
        }

        /// <summary>
        /// Polls for a just-stored item to become visible to a Secret Service
        /// lookup, closing the brief store-visibility window. Best-effort:
        /// returns after a bounded wait even if the item never appears, leaving
        /// any genuine failure to the caller's own lookup.
        /// </summary>
        private void ConfirmItemVisible(string providerName, string accountId)
        {
            const int maxAttempts = 20;
            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                if (LookupCredentialByAccountId(providerName, accountId) is not null)
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

                    // False only when the secret was actually asked for and did not
                    // arrive, matching the file backend's meaning of the flag: with
                    // no summary provider registered nothing is loaded, so there is
                    // nothing to report.
                    IsDecryptable = summaryProvider is null || i.Secret is not null,
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

            // Find the item so we know its provider (for selection cleanup).
            var match = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                    [AttrAccount] = accountId,
                },
                loadSecrets: false).FirstOrDefault();

            if (match is null)
            {
                return Task.FromResult(false);
            }

            var removed = ClearItem(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindCredential,
                [AttrAccount] = accountId,
            });

            if (!removed)
            {
                // The search found the item but the clear removed nothing — the collection
                // is locked, or it disappeared between the two calls. Reporting success
                // here told a user revoking a leaked credential that it was gone while it
                // was still readable by anything that can unlock the keyring. The selection
                // is deliberately left alone too: it still points at a credential that
                // exists.
                return Task.FromResult(false);
            }

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
            if (!IsValidAccountId(accountId))
            {
                return Task.FromResult(false);
            }

            var match = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                    [AttrAccount] = accountId,
                },
                loadSecrets: false).FirstOrDefault();

            if (match is null)
            {
                return Task.FromResult(false);
            }

            var providerName = match.Attributes.GetValueOrDefault(AttrProvider);
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

            return Task.FromResult(LookupCredentialByAccountId(providerName, selectedId));
        }

        /// <inheritdoc />
        public Task<string?> GetCredentialByIdAsync(string providerName, string accountId)
        {
            ValidateProviderName(providerName);
            providerName = ResolveStoredProviderName(providerName);
            ValidateAccountId(accountId);

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

        /// <inheritdoc />
        public Task<IReadOnlyList<CredentialExport>> ExportCredentialsAsync()
        {
            var items = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                },
                loadSecrets: true);

            var selectionCache = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

            var exports = new List<CredentialExport>();
            foreach (var item in items)
            {
                var providerName = item.Attributes.GetValueOrDefault(AttrProvider);
                if (string.IsNullOrEmpty(providerName))
                {
                    continue;
                }

                if (item.Secret is null)
                {
                    // The secret was requested but did not materialise. Reachable when
                    // the item vanished between the search and the retrieve, which
                    // libsecret reports as a NULL SecretValue *without* a GError. A
                    // locked collection or a per-item D-Bus error sets a GError instead
                    // and aborts the whole export via ThrowIfGError — per-item recovery
                    // from those is not attempted here.
                    //
                    // Skip it. CredentialData flows straight into the archive, so
                    // exporting an empty payload would write a valid-looking credential
                    // holding nothing, and the next import would restore that over a
                    // real secret. The caller reports the skipped count.
                    //
                    // Checked before the selection lookup so a skipped item costs no
                    // keyring round-trip.
                    continue;
                }

                if (!selectionCache.TryGetValue(providerName, out var selectedId))
                {
                    selectedId = ReadSelection(providerName);
                    selectionCache[providerName] = selectedId;
                }

                var accountId = item.Attributes.GetValueOrDefault(AttrAccount, string.Empty);

                exports.Add(new CredentialExport
                {
                    AccountId = accountId,
                    AccountName = item.Attributes.GetValueOrDefault(AttrLabel, string.Empty),
                    ProviderName = providerName,
                    Environment = item.Attributes.GetValueOrDefault(AttrEnvironment, string.Empty),
                    CredentialData = item.Secret,
                    CreatedAt = ParseCreatedAt(item.Attributes.GetValueOrDefault(AttrCreatedAt)),
                    IsSelected = selectedId is not null && string.Equals(selectedId, accountId, StringComparison.OrdinalIgnoreCase),
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

            // store overwrites an item whose attributes match exactly, so writing
            // with the same (app, kind, provider, account) replaces any existing
            // entry — a re-import is idempotent. CreatedAt is carried across
            // faithfully via the attribute.
            var attrs = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindCredential,
                [AttrProvider] = credential.ProviderName,
                [AttrAccount] = credential.AccountId,
                [AttrLabel] = credential.AccountName,
                [AttrEnvironment] = credential.Environment,
                [AttrCreatedAt] = credential.CreatedAt.ToString("O"),
            };
            var label = $"{_appIdentifier}: {credential.ProviderName}/{credential.AccountName}";

            StoreItem(attrs, label, credential.CredentialData);

            if (credential.IsSelected)
            {
                WriteSelection(credential.ProviderName, credential.AccountId);
            }

            return Task.CompletedTask;
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
            // Discard deliberately: clearing a selection that was never recorded is a
            // no-op, not a failure. Only DeleteCredentialAsync needs the result, because
            // there "nothing removed" means the credential is still stored.
            _ = ClearItem(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindSelection,
                [AttrProvider] = providerName,
            });
        }

        private static DateTime ParseCreatedAt(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return DateTime.MinValue;
            }

            return DateTime.TryParse(
                value,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.RoundtripKind,
                out var parsed)
                ? parsed
                : DateTime.MinValue;
        }

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
            var items = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                },
                loadSecrets: false);

            foreach (var item in items)
            {
                var stored = item.Attributes.GetValueOrDefault(AttrProvider);
                if (!string.IsNullOrEmpty(stored) &&
                    stored.Equals(providerName, StringComparison.OrdinalIgnoreCase))
                {
                    return stored;
                }
            }

            return providerName;
        }

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
                if (result == IntPtr.Zero)
                {
                    return null;
                }

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

        /// <summary>
        /// Removes every item matching <paramref name="attributes"/> and reports whether
        /// anything was actually removed.
        /// </summary>
        /// <returns>
        /// <see langword="true"/> when at least one item was removed.
        /// </returns>
        /// <remarks>
        /// The return value is load-bearing and must not be discarded again.
        /// <c>secret_password_clearv_sync</c> removes only <b>unlocked</b> matches and
        /// reports "nothing removed" by returning FALSE <em>without</em> setting a GError,
        /// so <see cref="ThrowIfGError"/> does not fire. Throwing the result away made
        /// <see cref="DeleteCredentialAsync"/> report success for a credential that is
        /// still in the keyring — a user revoking a leaked secret was told it was gone
        /// (#45).
        /// </remarks>
        private static bool ClearItem(Dictionary<string, string> attributes)
        {
            var attrs = NewAttributes(attributes);
            try
            {
                var removed = secret_password_clearv_sync(IntPtr.Zero, attrs, IntPtr.Zero, out var error);
                ThrowIfGError(error, "secret_password_clearv_sync");
                return removed != 0;
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
                if (listPtr == IntPtr.Zero)
                {
                    return results;
                }

                try
                {
                    var count = g_list_length(listPtr);
                    for (uint i = 0; i < count; i++)
                    {
                        var retrievable = g_list_nth_data(listPtr, i);
                        if (retrievable == IntPtr.Zero)
                        {
                            continue;
                        }

                        var itemAttrs = secret_retrievable_get_attributes(retrievable);
                        var managedAttrs = itemAttrs == IntPtr.Zero ? [] : ReadAttributes(itemAttrs);
                        if (itemAttrs != IntPtr.Zero)
                        {
                            g_hash_table_unref(itemAttrs);
                        }

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
                                if (secretValue != IntPtr.Zero)
                                {
                                    secret_value_unref(secretValue);
                                }
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
}

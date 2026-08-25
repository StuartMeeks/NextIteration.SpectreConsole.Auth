using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Commands;

using static NextIteration.SpectreConsole.Auth.Persistence.Libsecret.LibsecretInterop;

namespace NextIteration.SpectreConsole.Auth.Persistence.Libsecret
{
    /// <summary>
    /// <see cref="ICredentialManager"/> implementation backed by the Secret
    /// Service API (libsecret). Each credential becomes a libsecret item in
    /// the user's default keyring.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This backend is marked <b>experimental</b> and is validated against
    /// <c>gnome-keyring-daemon</c> only.
    /// </para>
    /// <para>
    /// <b>KWallet is not supported.</b> Its Secret Service shim (<c>ksecretd</c>) was
    /// tested and fails unattended in two ways (#19): it does not provide the
    /// <c>session</c> collection GNOME Keyring offers, so selecting it fails with
    /// <c>No such object path '/org/freedesktop/secrets/aliases/session'</c>; and against
    /// the default collection it raises a wallet-unlock prompt which, with no GUI, never
    /// completes.
    /// </para>
    /// <para>
    /// That second failure is <b>not</b> reachable by cancellation, and is worth recording
    /// precisely. ksecretd emits the prompt's <c>Completed</c> signal with an <c>ao</c>
    /// payload where libsecret expects <c>o</c>, so libsecret logs
    /// <c>received unexpected result type ao from Completed signal</c> and its
    /// <c>secret_service_real_prompt_async</c> GTask is then
    /// <c>finalized without ever returning</c>. The nested main loop the synchronous wrapper
    /// runs therefore never exits. Cancelling the <c>GCancellable</c> does fire — verified —
    /// but cannot rescue a task libsecret has already abandoned. It is an upstream
    /// incompatibility between libsecret and KWallet's shim, not something this backend can
    /// work around.
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
        public Task<string> AddCredentialAsync(string providerName, string accountName, string environment, string credentialData, CancellationToken cancellationToken = default)
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

            StoreItem(cancellationToken, attrs, label, credentialData);

            // A just-stored Secret Service item isn't always immediately visible
            // to a follow-up search under concurrent access, so a caller doing
            // add-then-select/delete can race the item's appearance. Confirm it's
            // queryable before returning so that can't happen.
            ConfirmItemVisible(providerName, accountId, cancellationToken);

            return Task.FromResult(accountId);
        }

        /// <summary>
        /// Polls for a just-stored item to become visible to a Secret Service
        /// lookup, closing the brief store-visibility window. Best-effort:
        /// returns after a bounded wait even if the item never appears, leaving
        /// any genuine failure to the caller's own lookup.
        /// </summary>
        private void ConfirmItemVisible(string providerName, string accountId, CancellationToken cancellationToken)
        {
            const int maxAttempts = 20;
            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                if (LookupCredentialByAccountId(providerName, accountId, cancellationToken) is not null)
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
        public Task<IEnumerable<CredentialSummary>> ListCredentialsAsync(string providerName, CancellationToken cancellationToken = default)
        {
            ValidateProviderName(providerName);
            providerName = ResolveStoredProviderName(providerName, cancellationToken);
            _summaryProviders.TryGetValue(providerName, out var summaryProvider);

            var selectedId = ReadSelection(providerName, cancellationToken);
            var items = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                    [AttrProvider] = providerName,
                },
                loadSecrets: summaryProvider is not null, cancellationToken);

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
        public Task<bool> DeleteCredentialAsync(string accountId, CancellationToken cancellationToken = default)
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
                loadSecrets: false, cancellationToken).FirstOrDefault();

            if (match is null)
            {
                return Task.FromResult(false);
            }

            var removed = ClearItem(cancellationToken, new Dictionary<string, string>(StringComparer.Ordinal)
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
                var selected = ReadSelection(providerName, cancellationToken);
                if (string.Equals(selected, accountId, StringComparison.OrdinalIgnoreCase))
                {
                    ClearSelection(providerName, cancellationToken);
                }
            }

            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public Task<bool> SelectCredentialAsync(string accountId, CancellationToken cancellationToken = default)
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
                loadSecrets: false, cancellationToken).FirstOrDefault();

            if (match is null)
            {
                return Task.FromResult(false);
            }

            var providerName = match.Attributes.GetValueOrDefault(AttrProvider);
            if (providerName is null)
            {
                return Task.FromResult(false);
            }

            WriteSelection(providerName, accountId, cancellationToken);
            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public Task<string?> GetSelectedCredentialAsync(string providerName, CancellationToken cancellationToken = default)
        {
            ValidateProviderName(providerName);
            providerName = ResolveStoredProviderName(providerName, cancellationToken);
            var selectedId = ReadSelection(providerName, cancellationToken);
            if (selectedId is null)
            {
                return Task.FromResult<string?>(null);
            }

            return Task.FromResult(LookupCredentialByAccountId(providerName, selectedId, cancellationToken));
        }

        /// <inheritdoc />
        public Task<string?> GetCredentialByIdAsync(string providerName, string accountId, CancellationToken cancellationToken = default)
        {
            ValidateProviderName(providerName);
            providerName = ResolveStoredProviderName(providerName, cancellationToken);
            ValidateAccountId(accountId);

            return Task.FromResult(LookupCredentialByAccountId(providerName, accountId, cancellationToken));
        }

        /// <summary>
        /// Secret Service lookup keyed on <c>(app, kind=credential, provider,
        /// account)</c>. Shared by <see cref="GetSelectedCredentialAsync"/>
        /// and <see cref="GetCredentialByIdAsync"/> — neither modifies the
        /// selection record.
        /// </summary>
        private string? LookupCredentialByAccountId(string providerName, string accountId, CancellationToken cancellationToken)
        {
            return LookupPassword(cancellationToken, new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindCredential,
                [AttrProvider] = providerName,
                [AttrAccount] = accountId,
            });
        }

        /// <inheritdoc />
        public Task<IEnumerable<string>> GetProviderNamesAsync(CancellationToken cancellationToken = default)
        {
            var items = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                },
                loadSecrets: false, cancellationToken);

            var names = items
                .Select(i => i.Attributes.GetValueOrDefault(AttrProvider))
                .Where(n => !string.IsNullOrEmpty(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.Ordinal)
                .ToList();

            return Task.FromResult<IEnumerable<string>>(names!);
        }

        /// <inheritdoc />
        public Task<IReadOnlyList<CredentialExport>> ExportCredentialsAsync(CancellationToken cancellationToken = default)
        {
            var items = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                },
                loadSecrets: true, cancellationToken);

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
                    selectedId = ReadSelection(providerName, cancellationToken);
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
        public Task RestoreCredentialAsync(CredentialExport credential, CancellationToken cancellationToken = default)
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

            StoreItem(cancellationToken, attrs, label, credential.CredentialData);

            if (credential.IsSelected)
            {
                WriteSelection(credential.ProviderName, credential.AccountId, cancellationToken);
            }

            return Task.CompletedTask;
        }

        // =========================
        // Internal helpers
        // =========================

        private string? ReadSelection(string providerName, CancellationToken cancellationToken)
        {
            return LookupPassword(cancellationToken, new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AttrApp] = _appIdentifier,
                [AttrKind] = KindSelection,
                [AttrProvider] = providerName,
            });
        }

        private void WriteSelection(string providerName, string accountId, CancellationToken cancellationToken)
        {
            // store overwrites an existing item with matching attributes, so
            // we don't need a separate add-or-update dance.
            StoreItem(
                cancellationToken,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindSelection,
                    [AttrProvider] = providerName,
                },
                label: $"{_appIdentifier}: active {providerName}",
                password: accountId);
        }

        private void ClearSelection(string providerName, CancellationToken cancellationToken)
        {
            // Discard deliberately: clearing a selection that was never recorded is a
            // no-op, not a failure. Only DeleteCredentialAsync needs the result, because
            // there "nothing removed" means the credential is still stored.
            _ = ClearItem(cancellationToken, new Dictionary<string, string>(StringComparer.Ordinal)
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
        private string ResolveStoredProviderName(string providerName, CancellationToken cancellationToken)
        {
            var items = SearchItems(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [AttrApp] = _appIdentifier,
                    [AttrKind] = KindCredential,
                },
                loadSecrets: false, cancellationToken);

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

        /// <summary>
        /// Binds a <see cref="CancellationToken"/> to a GCancellable for the lifetime of one
        /// libsecret call, so a blocked synchronous call can actually be made to return.
        /// </summary>
        /// <remarks>
        /// The Secret Service contract lets an implementation prompt — to unlock a collection,
        /// say — before serving a request, and the synchronous entry points here block until
        /// that prompt is answered. With no GUI nothing answers it. Passing NULL for the
        /// cancellable, as this backend used to, made that unrecoverable: KWallet's shim wedged
        /// a process so completely that SIGINT would not end it, only SIGKILL (#74).
        /// <para>
        /// <c>g_cancellable_cancel</c> is thread-safe, so the token callback can fire it from
        /// another thread while this one is blocked inside libsecret, and the call returns with
        /// a cancelled GError.
        /// </para>
        /// </remarks>
        private sealed class CancelScope : IDisposable
        {
            private readonly CancellationTokenRegistration _registration;

            internal CancelScope(CancellationToken cancellationToken)
            {
                Handle = g_cancellable_new();
                if (Handle == IntPtr.Zero)
                {
                    throw new InvalidOperationException("g_cancellable_new failed.");
                }

                // Registering an already-cancelled token invokes the callback immediately,
                // so a pre-cancelled call is cancelled before libsecret is even entered.
                _registration = cancellationToken.Register(
                    static state => g_cancellable_cancel((IntPtr)state!), Handle);
            }

            internal IntPtr Handle { get; }

            public void Dispose()
            {
                _registration.Dispose();
                g_object_unref(Handle);
            }
        }

        /// <summary>
        /// Frees <paramref name="error"/> and throws — <see cref="OperationCanceledException"/>
        /// when the caller cancelled, otherwise the usual wrapped GError.
        /// </summary>
        /// <remarks>
        /// Cancellation is checked first on purpose. libsecret reports a cancelled call as a
        /// GError, and reporting that as a generic "operation failed" would hide the fact that
        /// the caller asked for it.
        /// </remarks>
        private static void ThrowIfCancelledOrGError(IntPtr error, string operation, CancellationToken cancellationToken)
        {
            if (error != IntPtr.Zero && cancellationToken.IsCancellationRequested)
            {
                g_error_free(error);
                cancellationToken.ThrowIfCancellationRequested();
            }

            ThrowIfGError(error, operation);
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

        private void StoreItem(CancellationToken cancellationToken, Dictionary<string, string> attributes, string label, string password)
        {
            var attrs = NewAttributes(attributes);
            try
            {
                using var cancel = new CancelScope(cancellationToken);
                var status = secret_password_storev_sync(
                    IntPtr.Zero,
                    attrs,
                    _collection,
                    label,
                    password,
                    cancel.Handle,
                    out var error);
                ThrowIfCancelledOrGError(error, "secret_password_storev_sync", cancellationToken);
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

        private static string? LookupPassword(CancellationToken cancellationToken, Dictionary<string, string> attributes)
        {
            var attrs = NewAttributes(attributes);
            try
            {
                using var cancel = new CancelScope(cancellationToken);
                var result = secret_password_lookupv_sync(IntPtr.Zero, attrs, cancel.Handle, out var error);
                ThrowIfCancelledOrGError(error, "secret_password_lookupv_sync", cancellationToken);
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
        private static bool ClearItem(CancellationToken cancellationToken, Dictionary<string, string> attributes)
        {
            var attrs = NewAttributes(attributes);
            try
            {
                using var cancel = new CancelScope(cancellationToken);
                var removed = secret_password_clearv_sync(IntPtr.Zero, attrs, cancel.Handle, out var error);
                ThrowIfCancelledOrGError(error, "secret_password_clearv_sync", cancellationToken);
                return removed != 0;
            }
            finally
            {
                g_hash_table_unref(attrs);
            }
        }

        private static List<StoredItem> SearchItems(Dictionary<string, string> attributes, bool loadSecrets, CancellationToken cancellationToken)
        {
            var attrs = NewAttributes(attributes);
            var flags = SecretSearchAll | (loadSecrets ? SecretSearchLoadSecrets | SecretSearchUnlock : 0);
            try
            {
                using var cancel = new CancelScope(cancellationToken);
                var listPtr = secret_password_searchv_sync(IntPtr.Zero, attrs, flags, cancel.Handle, out var error);
                ThrowIfCancelledOrGError(error, "secret_password_searchv_sync", cancellationToken);

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
                            var secretValue = secret_retrievable_retrieve_secret_sync(retrievable, cancel.Handle, out var secretError);
                            ThrowIfCancelledOrGError(secretError, "secret_retrievable_retrieve_secret_sync", cancellationToken);
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
                    }
                }
                finally
                {
                    // g_list_free_full releases every node's data as well as the node
                    // structure. The per-item g_object_unref used to sit at the end of the
                    // loop body, so a throw part-way through — ThrowIfGError on a locked
                    // collection or a per-item D-Bus error — skipped the current item and
                    // every remaining one, while this finally freed only the node structure
                    // and not the references the nodes held (#56).
                    g_list_free_full(listPtr, GObjectUnrefFunc);
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

using NextIteration.SpectreConsole.Auth.Persistence;

namespace NextIteration.SpectreConsole.Auth.Portability
{
    /// <summary>
    /// How an import should treat an incoming credential that collides with an
    /// existing one (same provider, account name, and environment).
    /// </summary>
    internal enum ConflictResolution
    {
        /// <summary>Leave the existing credential untouched; drop the incoming one.</summary>
        Skip,

        /// <summary>Replace the existing credential with the incoming one.</summary>
        Overwrite,
    }

    /// <summary>Outcome of an <see cref="CredentialPortabilityService.ExportAsync"/> call.</summary>
    /// <param name="Bundle">The passphrase-encrypted archive text.</param>
    /// <param name="Count">Number of credentials written into the archive.</param>
    /// <param name="Skipped">
    /// Stored credentials left out because their payload could not be decrypted.
    /// Surfaced so the command can warn: a silently short archive is a data-loss
    /// trap, since the missing secrets look like they were never stored.
    /// </param>
    internal sealed record ExportResult(string Bundle, int Count, int Skipped);

    /// <summary>Outcome of an <see cref="CredentialPortabilityService.ImportAsync"/> call.</summary>
    /// <param name="Added">Credentials that did not exist and were created.</param>
    /// <param name="Overwritten">Existing credentials that were replaced.</param>
    /// <param name="Skipped">Colliding credentials left untouched.</param>
    internal sealed record ImportResult(int Added, int Overwritten, int Skipped);

    /// <summary>
    /// Backend-agnostic orchestration for whole-store export and import. Sits
    /// entirely above <see cref="ICredentialManager"/> so it works uniformly
    /// across the file, Keychain, and libsecret backends, and is unit-testable
    /// without the interactive command layer (the conflict decision is injected
    /// as a delegate).
    /// </summary>
    internal sealed class CredentialPortabilityService
    {
        private readonly ICredentialManager _manager;

        internal CredentialPortabilityService(ICredentialManager manager)
        {
            ArgumentNullException.ThrowIfNull(manager);
            _manager = manager;
        }

        /// <summary>
        /// Reads every stored credential and returns it as a passphrase-encrypted
        /// archive.
        /// </summary>
        internal async Task<ExportResult> ExportAsync(string passphrase)
        {
            var credentials = await _manager.ExportCredentialsAsync().ConfigureAwait(false);
            var bundle = CredentialArchive.Serialize(credentials, passphrase);

            // The backend drops credentials it cannot decrypt, so the archive may
            // hold fewer than the store does. Derive the difference from the
            // metadata listing rather than widening the public
            // ICredentialManager.ExportCredentialsAsync signature to report it.
            var stored = await CountStoredCredentialsAsync().ConfigureAwait(false);
            return new ExportResult(bundle, credentials.Count, Math.Max(0, stored - credentials.Count));
        }

        /// <summary>
        /// Decrypts an archive and restores its credentials into the store.
        /// A credential that matches an existing one on (provider, account name,
        /// environment) is routed to <paramref name="resolveConflict"/> to decide
        /// skip vs. overwrite; a credential with no match is added.
        /// </summary>
        /// <param name="bundle">The archive text produced by <see cref="ExportAsync"/>.</param>
        /// <param name="passphrase">The passphrase the archive was written with.</param>
        /// <param name="resolveConflict">
        /// Called once per collision with (incoming, existing) and returns how to
        /// resolve it. Invoked only when there is an actual conflict. The existing
        /// side is metadata only — see <see cref="BuildConflictIndexAsync"/>.
        /// </param>
        internal async Task<ImportResult> ImportAsync(
            string bundle,
            string passphrase,
            Func<CredentialExport, CredentialSummary, ConflictResolution> resolveConflict)
        {
            ArgumentNullException.ThrowIfNull(resolveConflict);

            var incoming = CredentialArchive.Deserialize(bundle, passphrase);
            var existingByKey = await BuildConflictIndexAsync().ConfigureAwait(false);

            var added = 0;
            var overwritten = 0;
            var skipped = 0;

            foreach (var entry in incoming)
            {
                if (existingByKey.TryGetValue(ConflictKey(entry), out var match))
                {
                    var resolution = resolveConflict(entry, match);
                    if (resolution == ConflictResolution.Skip)
                    {
                        skipped++;
                        continue;
                    }

                    // Overwrite: drop the existing credential (which may carry a
                    // different account id) before restoring the incoming one.
                    _ = await _manager.DeleteCredentialAsync(match.AccountId).ConfigureAwait(false);
                    await _manager.RestoreCredentialAsync(entry).ConfigureAwait(false);
                    overwritten++;
                }
                else
                {
                    await _manager.RestoreCredentialAsync(entry).ConfigureAwait(false);
                    added++;
                }
            }

            return new ImportResult(added, overwritten, skipped);
        }

        /// <summary>
        /// Indexes the credentials already in the store by their semantic identity,
        /// reading <b>metadata only</b>.
        /// </summary>
        /// <remarks>
        /// Deliberately not <see cref="ICredentialManager.ExportCredentialsAsync"/>.
        /// Conflict detection needs only the provider, account name and environment
        /// — all stored in plaintext — never the encrypted payload. Decrypting the
        /// whole store to build this index was both wasteful (every secret
        /// materialised in memory for an operation that never reads one) and fatal:
        /// a single credential the local keystore cannot open aborted the entire
        /// import, which is exactly the store an import is meant to repair.
        /// </remarks>
        private async Task<Dictionary<string, CredentialSummary>> BuildConflictIndexAsync()
        {
            var index = new Dictionary<string, CredentialSummary>(StringComparer.Ordinal);

            foreach (var provider in await _manager.GetProviderNamesAsync().ConfigureAwait(false))
            {
                foreach (var summary in await _manager.ListCredentialsAsync(provider).ConfigureAwait(false))
                {
                    // Duplicates on the same key are unusual but possible; keep the
                    // first as the conflict target.
                    _ = index.TryAdd(
                        ConflictKey(summary.ProviderName, summary.AccountName, summary.Environment),
                        summary);
                }
            }

            return index;
        }

        /// <summary>
        /// Counts what the store holds, from metadata only, so an export can report
        /// how many credentials it had to leave out.
        /// </summary>
        private async Task<int> CountStoredCredentialsAsync()
        {
            var count = 0;
            foreach (var provider in await _manager.GetProviderNamesAsync().ConfigureAwait(false))
            {
                count += (await _manager.ListCredentialsAsync(provider).ConfigureAwait(false)).Count();
            }

            return count;
        }

        private static string ConflictKey(CredentialExport c) =>
            ConflictKey(c.ProviderName, c.AccountName, c.Environment);

        // Semantic identity used to detect "the same" credential across machines,
        // where account ids differ. Case-insensitive on all three parts, and
        // length-prefixed so no combination of separators inside a value can make
        // two different triples collide onto one key.
        private static string ConflictKey(string providerName, string accountName, string environment)
        {
            var provider = providerName.ToLowerInvariant();
            var name = accountName.ToLowerInvariant();
            var env = environment.ToLowerInvariant();
            return $"{provider.Length}:{provider}|{name.Length}:{name}|{env.Length}:{env}";
        }
    }
}

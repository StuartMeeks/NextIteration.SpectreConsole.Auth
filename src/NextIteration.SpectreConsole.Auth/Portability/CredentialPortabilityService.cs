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
    internal sealed record ExportResult(string Bundle, int Count);

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
            return new ExportResult(bundle, credentials.Count);
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
        /// resolve it. Invoked only when there is an actual conflict.
        /// </param>
        internal async Task<ImportResult> ImportAsync(
            string bundle,
            string passphrase,
            Func<CredentialExport, CredentialExport, ConflictResolution> resolveConflict)
        {
            ArgumentNullException.ThrowIfNull(resolveConflict);

            var incoming = CredentialArchive.Deserialize(bundle, passphrase);
            var existing = await _manager.ExportCredentialsAsync().ConfigureAwait(false);

            // Index existing credentials by their semantic identity. Duplicates
            // on the same key are unusual but possible; keep the first as the
            // conflict target.
            var existingByKey = new Dictionary<string, CredentialExport>(StringComparer.Ordinal);
            foreach (var e in existing)
            {
                _ = existingByKey.TryAdd(ConflictKey(e), e);
            }

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

        // Semantic identity used to detect "the same" credential across machines,
        // where account ids differ. Case-insensitive on all three parts, and
        // length-prefixed so no combination of separators inside a value can make
        // two different triples collide onto one key.
        private static string ConflictKey(CredentialExport c)
        {
            var provider = c.ProviderName.ToLowerInvariant();
            var name = c.AccountName.ToLowerInvariant();
            var environment = c.Environment.ToLowerInvariant();
            return $"{provider.Length}:{provider}|{name.Length}:{name}|{environment.Length}:{environment}";
        }
    }
}

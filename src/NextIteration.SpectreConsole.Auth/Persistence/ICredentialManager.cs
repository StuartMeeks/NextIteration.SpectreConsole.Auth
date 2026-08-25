using NextIteration.SpectreConsole.Auth.Commands;

namespace NextIteration.SpectreConsole.Auth.Persistence
{
    /// <summary>
    /// Storage interface for encrypted credentials. The default
    /// implementation is <see cref="FileCredentialManager"/>, registered
    /// automatically by <c>AddCredentialStore</c>.
    /// </summary>
    public interface ICredentialManager
    {
        /// <summary>
        /// Lists all stored credentials for a specific provider.
        /// </summary>
        /// <param name="providerName">The provider (e.g. <c>Adobe</c>).</param>
        Task<IEnumerable<CredentialSummary>> ListCredentialsAsync(string providerName);

        /// <summary>
        /// Stores a new credential and returns its generated account ID.
        /// </summary>
        /// <param name="providerName">Provider (e.g. <c>Adobe</c>).</param>
        /// <param name="accountName">User-supplied display name for the credential.</param>
        /// <param name="environment">Environment the credential targets (e.g. <c>Production</c>).</param>
        /// <param name="credentialData">Plaintext JSON payload to encrypt and persist.</param>
        /// <returns>The account ID assigned to the new credential (a GUID).</returns>
        Task<string> AddCredentialAsync(string providerName, string accountName, string environment, string credentialData);

        /// <summary>
        /// Deletes a credential by its account ID, and clears any selection
        /// that pointed to it.
        /// </summary>
        /// <returns><see langword="true"/> if the credential existed and was deleted.</returns>
        Task<bool> DeleteCredentialAsync(string accountId);

        /// <summary>
        /// Marks the credential as the active one for its provider. Exactly
        /// one credential per provider may be selected at a time.
        /// </summary>
        /// <returns><see langword="true"/> if the credential was found and selected.</returns>
        Task<bool> SelectCredentialAsync(string accountId);

        /// <summary>
        /// Returns the decrypted JSON payload of the currently selected
        /// credential for <paramref name="providerName"/>, or
        /// <see langword="null"/> if no credential is selected.
        /// </summary>
        Task<string?> GetSelectedCredentialAsync(string providerName);

        /// <summary>
        /// Returns the decrypted JSON payload of a specific credential by
        /// its account id, without changing which credential is currently
        /// selected. Use this when you need to read a non-active credential
        /// (e.g. to resolve one of several stored credentials at runtime by
        /// some lookup key) — it's the non-mutating counterpart to
        /// <see cref="GetSelectedCredentialAsync"/>.
        /// </summary>
        /// <param name="providerName">The provider (e.g. <c>Adobe</c>).</param>
        /// <param name="accountId">The account id (GUID) returned by <see cref="AddCredentialAsync"/>.</param>
        /// <returns>
        /// The decrypted JSON payload, or <see langword="null"/> if no
        /// credential with that account id exists for the given provider.
        /// </returns>
        Task<string?> GetCredentialByIdAsync(string providerName, string accountId);

        /// <summary>
        /// Returns the set of provider names that currently have at least
        /// one stored credential.
        /// </summary>
        Task<IEnumerable<string>> GetProviderNamesAsync();

        /// <summary>
        /// Enumerates the stored credentials across all providers whose payload can
        /// be read, each with its <b>decrypted</b> payload and current selection
        /// state. This is the read half of the export/import feature and the
        /// counterpart to <see cref="RestoreCredentialAsync"/>.
        /// </summary>
        /// <returns>
        /// A snapshot of the readable stored credentials as
        /// <see cref="CredentialExport"/> records. The list is empty when nothing is
        /// stored, or when nothing stored can be read.
        /// </returns>
        /// <remarks>
        /// <para>
        /// Unlike <see cref="CredentialSummary"/>, the returned records carry
        /// the plaintext <see cref="CredentialExport.CredentialData"/>. Handle
        /// the result as secret material: never log it and don't persist it
        /// unencrypted.
        /// </para>
        /// <para>
        /// <b>Implementations must omit a credential they cannot read</b> — one whose
        /// ciphertext fails to decrypt, or whose secret does not load from an OS store
        /// — rather than returning it with an empty
        /// <see cref="CredentialExport.CredentialData"/>. The result is serialised into
        /// portable archives, where an empty payload is indistinguishable from a real
        /// one and silently overwrites the genuine secret on the next restore. This
        /// means the returned count can be lower than the number of stored credentials;
        /// callers that need to report the shortfall should compare against
        /// <see cref="ListCredentialsAsync"/>, which reads metadata only.
        /// </para>
        /// </remarks>
        Task<IReadOnlyList<CredentialExport>> ExportCredentialsAsync();

        /// <summary>
        /// Recreates a credential from an export record, preserving its
        /// <see cref="CredentialExport.AccountId"/>, its
        /// <see cref="CredentialExport.CreatedAt"/> (where the backend allows
        /// it), and its selection state. Any existing credential with the same
        /// <see cref="CredentialExport.ProviderName"/> and
        /// <see cref="CredentialExport.AccountId"/> is replaced.
        /// </summary>
        /// <param name="credential">
        /// The record to restore. Its <see cref="CredentialExport.CredentialData"/>
        /// is the plaintext payload and is re-protected by the backend on write.
        /// </param>
        /// <remarks>
        /// The record's <see cref="CredentialExport.ProviderName"/> and
        /// <see cref="CredentialExport.AccountId"/> are validated before use —
        /// this method is fed from imported archives, which are untrusted input.
        /// The macOS Keychain backend assigns its own creation timestamp, so a
        /// restored item's <see cref="CredentialExport.CreatedAt"/> is not
        /// preserved there.
        /// </remarks>
        Task RestoreCredentialAsync(CredentialExport credential);
    }

    /// <summary>
    /// Non-sensitive metadata about a stored credential, suitable for
    /// display in the <c>accounts list</c> command. The encrypted payload
    /// itself is never exposed through this type.
    /// </summary>
    public class CredentialSummary
    {
        /// <summary>Unique GUID assigned at creation time.</summary>
        public required string AccountId { get; init; }

        /// <summary>User-supplied display name.</summary>
        public required string AccountName { get; init; }

        /// <summary>Provider this credential belongs to.</summary>
        public required string ProviderName { get; init; }

        /// <summary>Environment the credential targets.</summary>
        public required string Environment { get; init; }

        /// <summary>Timestamp at which the credential was added.</summary>
        public required DateTime CreatedAt { get; init; }

        /// <summary>
        /// True when this credential is the currently active one for its provider.
        /// </summary>
        public required bool IsSelected { get; init; }

        /// <summary>
        /// Provider-specific label/value pairs projected from the decrypted
        /// credential by the registered <see cref="ICredentialSummaryProvider"/>.
        /// Empty when no summary provider is registered for this provider, and
        /// also when the payload could not be decrypted — see
        /// <see cref="IsDecryptable"/> to tell those apart.
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, string>> DisplayFields { get; init; } = [];

        /// <summary>
        /// Display hint: <see langword="false"/> when this credential's provider
        /// columns could not be produced, so <see cref="DisplayFields"/> is empty for
        /// that reason rather than because no summary provider is registered. Either
        /// the payload itself was unavailable — it failed to decrypt (file backend) or
        /// did not load from the OS store (Keychain, libsecret) — or the registered
        /// <see cref="ICredentialSummaryProvider"/> threw while projecting it.
        /// </summary>
        /// <remarks>
        /// This is not a guarantee that the payload <em>is</em> readable. The
        /// payload is only read when an <see cref="ICredentialSummaryProvider"/> is
        /// registered for the provider; with none registered nothing is decrypted
        /// and this stays <see langword="true"/> even for an unreadable credential.
        /// Callers that must know for certain should attempt
        /// <see cref="ICredentialManager.GetCredentialByIdAsync"/>, which throws on
        /// an unreadable payload rather than hiding it.
        /// </remarks>
        public bool IsDecryptable { get; init; } = true;
    }

    /// <summary>
    /// A full-fidelity, portable snapshot of a single stored credential,
    /// including its <b>decrypted</b> payload. Produced by
    /// <see cref="ICredentialManager.ExportCredentialsAsync"/> and consumed by
    /// <see cref="ICredentialManager.RestoreCredentialAsync"/> to move
    /// credentials between machines.
    /// </summary>
    /// <remarks>
    /// This type carries secret material in <see cref="CredentialData"/>.
    /// Callers that serialise it — for example the <c>accounts export</c>
    /// command — must encrypt the result before it touches disk; the built-in
    /// export path protects it with a user-supplied passphrase.
    /// </remarks>
    public sealed class CredentialExport
    {
        /// <summary>Unique GUID assigned at the credential's original creation time.</summary>
        public required string AccountId { get; init; }

        /// <summary>User-supplied display name.</summary>
        public required string AccountName { get; init; }

        /// <summary>Provider this credential belongs to.</summary>
        public required string ProviderName { get; init; }

        /// <summary>Environment the credential targets.</summary>
        public required string Environment { get; init; }

        /// <summary>
        /// The decrypted, plaintext credential payload (the same JSON that was
        /// passed to <see cref="ICredentialManager.AddCredentialAsync"/>).
        /// </summary>
        public required string CredentialData { get; init; }

        /// <summary>Timestamp at which the credential was originally added.</summary>
        public required DateTime CreatedAt { get; init; }

        /// <summary>
        /// True when this credential was the active one for its provider at
        /// export time. A restored credential with this set is re-selected.
        /// </summary>
        public required bool IsSelected { get; init; }
    }
}

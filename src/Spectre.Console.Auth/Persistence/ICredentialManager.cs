using Spectre.Console.Auth.Commands;

namespace Spectre.Console.Auth.Persistence
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
        /// Returns the set of provider names that currently have at least
        /// one stored credential.
        /// </summary>
        Task<IEnumerable<string>> GetProviderNamesAsync();
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
        /// Empty when no summary provider is registered for this provider.
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, string>> DisplayFields { get; init; } = [];
    }
}

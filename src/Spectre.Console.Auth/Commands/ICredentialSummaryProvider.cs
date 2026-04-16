namespace Spectre.Console.Auth.Commands
{
    /// <summary>
    /// Projects a decrypted credential into an ordered list of human-readable
    /// label/value pairs for display in the <c>accounts list</c> command.
    /// Each provider registers one implementation in DI; the credential
    /// manager calls it during <see cref="Persistence.ICredentialManager.ListCredentialsAsync"/>.
    /// </summary>
    /// <remarks>
    /// Implementations should return only non-sensitive data or masked
    /// fingerprints of sensitive data (e.g. first/last four characters of an
    /// API token). The returned values are rendered in a terminal table and
    /// may be shown to the user in screenshots, screen shares, or logs.
    /// </remarks>
    public interface ICredentialSummaryProvider
    {
        /// <summary>
        /// The provider name this summary provider handles. Must match the
        /// <c>ProviderName</c> of the corresponding
        /// <see cref="Credentials.ICredential"/> implementation.
        /// </summary>
        string ProviderName { get; }

        /// <summary>
        /// Returns an ordered list of label/value pairs describing the
        /// credential. Order is preserved when rendering columns.
        /// </summary>
        /// <param name="decryptedCredentialJson">
        /// The decrypted credential data, as produced by the collector at
        /// add time. The implementation is responsible for deserialising it
        /// into its concrete credential type.
        /// </param>
        IReadOnlyList<KeyValuePair<string, string>> GetDisplayFields(string decryptedCredentialJson);
    }
}

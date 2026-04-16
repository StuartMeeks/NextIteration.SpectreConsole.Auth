namespace Spectre.Console.Auth
{
    /// <summary>
    /// Provider-specific contributor that knows how to prompt the user for the data
    /// needed to add a new credential. Register one implementation per provider in DI.
    /// </summary>
    public interface ICredentialCollector
    {
        /// <summary>
        /// The provider name shown in the provider-selection prompt and stored with the
        /// credential. Must match the <c>ProviderName</c> used by the associated
        /// <see cref="Credentials.ICredential"/> implementation.
        /// </summary>
        string ProviderName { get; }

        /// <summary>
        /// Prompts the user for the credential details and returns the serialized
        /// credential JSON together with the selected environment name.
        /// </summary>
        Task<(string credentialData, string environment)> CollectAsync();
    }
}

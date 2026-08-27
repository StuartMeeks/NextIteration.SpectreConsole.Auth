namespace NextIteration.SpectreConsole.Auth.Commands
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
        /// <param name="cancellationToken">
        /// Cancels the prompts. Pass it to Spectre.Console's <c>PromptAsync</c> /
        /// <c>ConfirmAsync</c> overloads — an implementation that ignores it leaves
        /// <c>accounts add</c> unable to be interrupted while it waits for input, which is
        /// unbounded by nature since it waits on a human.
        /// </param>
        Task<(string credentialData, string environment)> CollectAsync(CancellationToken cancellationToken = default);
    }
}

namespace NextIteration.SpectreConsole.Auth.Credentials
{
    /// <summary>
    /// Contract implemented by every concrete credential type. Each provider
    /// defines its own implementation carrying provider-specific secrets
    /// (API keys, tokens, URLs, etc.) and the environment the credential
    /// targets.
    /// </summary>
    public interface ICredential
    {
        /// <summary>
        /// Provider name used to group and look up credentials on disk.
        /// Must be unique across providers and stable across versions — it
        /// is embedded in the filename of each stored credential.
        /// </summary>
        public abstract static string ProviderName { get; }

        /// <summary>
        /// List of environment names the provider accepts (for example
        /// <c>Production</c>, <c>Staging</c>). Used to populate the
        /// environment-selection prompt during <c>accounts add</c>.
        /// </summary>
        public abstract static List<string> SupportedEnvironments { get; }

        /// <summary>
        /// The environment this particular credential instance targets.
        /// Must be one of the values returned by <see cref="SupportedEnvironments"/>.
        /// </summary>
        public abstract string Environment { get; }
    }
}

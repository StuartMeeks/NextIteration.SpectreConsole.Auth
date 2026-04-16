namespace Spectre.Console.Auth
{
    /// <summary>
    /// Options passed to <c>AddCredentialStore</c> to configure the credential store.
    /// </summary>
    public sealed class CredentialStoreOptions
    {
        /// <summary>
        /// Absolute path to the directory where encrypted credential files and the
        /// keystore are stored. Required.
        /// </summary>
        public string CredentialsDirectory { get; set; } = string.Empty;
    }
}

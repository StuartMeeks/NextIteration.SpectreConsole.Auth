using Spectre.Console.Auth.Credentials;
using Spectre.Console.Auth.Tokens;

namespace Spectre.Console.Auth.Services
{
    /// <summary>
    /// Provider-specific authentication service that exchanges a credential
    /// for a token. Implementations typically call the provider's auth
    /// endpoint (OAuth2, static-token pass-through, etc.).
    /// </summary>
    /// <typeparam name="TCredential">The concrete credential type for this provider.</typeparam>
    /// <typeparam name="TToken">The concrete token type for this provider.</typeparam>
    public interface IAuthenticationService<TCredential, TToken>
        where TCredential : ICredential
        where TToken : IToken
    {
        /// <summary>
        /// Authenticates using whichever credential is currently selected
        /// for this provider via <see cref="Persistence.ICredentialManager.SelectCredentialAsync"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// No credential is currently selected for this provider, or the
        /// stored credential failed to deserialize.
        /// </exception>
        Task<TToken> AuthenticateAsync();

        /// <summary>
        /// Authenticates using the supplied credential directly, bypassing
        /// the selection mechanism.
        /// </summary>
        Task<TToken> AuthenticateAsync(TCredential credential);

        /// <summary>
        /// Returns <see langword="true"/> when the supplied token is still
        /// valid (not expired and not revoked by the provider).
        /// </summary>
        Task<bool> ValidateTokenAsync(TToken token);
    }
}

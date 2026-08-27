using NextIteration.SpectreConsole.Auth.Credentials;
using NextIteration.SpectreConsole.Auth.Tokens;

namespace NextIteration.SpectreConsole.Auth.Services
{
    /// <summary>
    /// Provider-specific authentication service that exchanges a credential
    /// for a token. Implementations typically call the provider's auth
    /// endpoint (OAuth2, static-token pass-through, etc.).
    /// </summary>
    /// <typeparam name="TCredential">The concrete credential type for this provider.</typeparam>
    /// <typeparam name="TToken">The concrete token type for this provider.</typeparam>
    /// <remarks>
    /// Every member takes a <see cref="CancellationToken"/> and implementations are expected
    /// to honour it. This is the layer that talks to the network — an OAuth2 token endpoint,
    /// a validation call — so it is where an unbounded wait is most likely and least
    /// recoverable. <see cref="Persistence.ICredentialManager"/> gained cancellation for the
    /// same reason; leaving it off here would have made the storage layer, which is local and
    /// fast, the only cancellable half.
    /// </remarks>
    public interface IAuthenticationService<TCredential, TToken>
        where TCredential : ICredential
        where TToken : IToken
    {
        /// <summary>
        /// Authenticates using whichever credential is currently selected
        /// for this provider via <see cref="Persistence.ICredentialManager.SelectCredentialAsync"/>.
        /// </summary>
        /// <param name="cancellationToken">Cancels the lookup and the authentication call.</param>
        /// <exception cref="InvalidOperationException">
        /// No credential is currently selected for this provider, or the
        /// stored credential failed to deserialize.
        /// </exception>
        Task<TToken> AuthenticateAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Authenticates using the supplied credential directly, bypassing
        /// the selection mechanism.
        /// </summary>
        /// <param name="credential">The credential to authenticate with.</param>
        /// <param name="cancellationToken">Cancels the authentication call.</param>
        Task<TToken> AuthenticateAsync(TCredential credential, CancellationToken cancellationToken = default);

        /// <summary>
        /// Returns <see langword="true"/> when the supplied token is still
        /// valid (not expired and not revoked by the provider).
        /// </summary>
        /// <param name="token">The token to check.</param>
        /// <param name="cancellationToken">Cancels the validation call.</param>
        Task<bool> ValidateTokenAsync(TToken token, CancellationToken cancellationToken = default);
    }
}

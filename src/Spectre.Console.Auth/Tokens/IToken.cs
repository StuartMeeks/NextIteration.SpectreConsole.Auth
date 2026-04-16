namespace Spectre.Console.Auth.Tokens
{
    /// <summary>
    /// A token produced by authenticating with a credential. Exposes only
    /// what's needed to attach the token to an outgoing request and to
    /// decide whether the token is still usable.
    /// </summary>
    public interface IToken
    {
        /// <summary>
        /// True when the token has expired and must be refreshed before
        /// further use. Tokens that never expire (e.g. long-lived API
        /// tokens) can return <see langword="false"/> unconditionally.
        /// </summary>
        bool IsExpired { get; }

        /// <summary>
        /// Returns the value to assign to the HTTP <c>Authorization</c>
        /// header when making requests with this token (for example
        /// <c>Bearer {accessToken}</c>).
        /// </summary>
        string GetAuthorizationHeader();
    }
}

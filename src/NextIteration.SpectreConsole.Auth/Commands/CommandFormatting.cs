namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Display helpers shared across the <c>accounts</c> commands. Centralised
    /// so an unusually short or malformed account id (e.g. a tampered file on
    /// disk, or a user-supplied id that didn't pass GUID parsing) doesn't
    /// crash the command via an out-of-range slice.
    /// </summary>
    internal static class CommandFormatting
    {
        /// <summary>
        /// Returns a display-friendly abbreviation of an account id. Library
        /// account ids are GUIDs (36 chars), but on the user-supplied path
        /// we may receive arbitrarily short strings before validation has
        /// run — falling back to the full string keeps error messages
        /// useful instead of throwing.
        /// </summary>
        internal static string ShortId(string? accountId)
        {
            if (string.IsNullOrEmpty(accountId)) return string.Empty;
            return accountId.Length >= 8 ? accountId[..8] + "..." : accountId;
        }
    }
}

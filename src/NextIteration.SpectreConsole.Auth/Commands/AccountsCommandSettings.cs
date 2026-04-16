using Spectre.Console.Cli;
using System.ComponentModel;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Base CLI settings shared by every command in the <c>accounts</c>
    /// branch. Carries the common <c>--verbose</c> flag that toggles
    /// full stack-trace rendering when a command fails.
    /// </summary>
    public class AccountsCommandSettings : CommandSettings
    {
        /// <summary>
        /// When <see langword="true"/>, the command prints the full
        /// exception (type, message, stack trace) on failure instead of
        /// only the message. Useful when diagnosing integration issues.
        /// </summary>
        [CommandOption("-v|--verbose")]
        [Description("Show full stack traces on error")]
        public bool Verbose { get; set; }
    }
}

using Spectre.Console;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Centralised error rendering for the <c>accounts</c> commands so
    /// every command's catch block uses the same behaviour — terse
    /// single-line message by default, full exception when <c>--verbose</c>
    /// is set.
    /// </summary>
    internal static class CommandErrorReporter
    {
        /// <summary>
        /// Writes <paramref name="ex"/> to the console. In verbose mode
        /// the full <see cref="Spectre.Console.AnsiConsole"/> exception
        /// view is rendered; otherwise a single coloured line prefixed
        /// with <paramref name="contextMessage"/>.
        /// </summary>
        internal static void Report(Exception ex, string contextMessage, bool verbose)
        {
            if (verbose)
            {
                AnsiConsole.MarkupLine($"[red]{contextMessage}[/]");
                AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]{contextMessage}: {ex.Message}[/]");
                AnsiConsole.MarkupLine("[grey]Run with --verbose for more detail.[/]");
            }
        }
    }
}

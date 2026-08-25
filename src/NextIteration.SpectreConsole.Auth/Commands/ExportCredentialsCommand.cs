using System.ComponentModel;

using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Portability;

using Spectre.Console;
using Spectre.Console.Cli;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Spectre.Console command for the <c>accounts export</c> branch. Writes
    /// every stored credential to a single passphrase-encrypted archive file so
    /// the whole set can be moved to another machine and re-imported with
    /// <see cref="ImportCredentialsCommand"/>.
    /// </summary>
    /// <remarks>DI constructor.</remarks>
    public sealed class ExportCredentialsCommand(ICredentialManager credentialManager) : AsyncCommand<ExportCredentialsCommand.Settings>
    {
        private readonly ICredentialManager _credentialManager = credentialManager;

        /// <inheritdoc />
        protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (File.Exists(settings.File) && !settings.Force)
                {
                    AnsiConsole.MarkupLine($"[red]File already exists: {Markup.Escape(settings.File)}. Pass --force to overwrite.[/]");
                    return 1;
                }

                var passphrase = await ResolveExportPassphraseAsync(settings, cancellationToken).ConfigureAwait(false);
                if (passphrase is null)
                {
                    // ResolveExportPassphraseAsync has already reported why.
                    return 1;
                }

                var service = new CredentialPortabilityService(_credentialManager);
                var result = await service.ExportAsync(passphrase, cancellationToken).ConfigureAwait(false);

                if (result.Count == 0)
                {
                    // All-unreadable is a very different situation from an empty
                    // store, and reporting it as "nothing to export" would hide a
                    // broken store behind a success message.
                    AnsiConsole.MarkupLine(result.Skipped > 0
                        ? $"[red]Nothing exported: all {result.Skipped} stored credential(s) failed to decrypt with this machine's keystore.[/]"
                        : "[yellow]No credentials to export.[/]");
                    return result.Skipped > 0 ? 1 : 0;
                }

                // 0600 on Unix so the archive isn't world-readable while it sits
                // on disk; on Windows it inherits the directory ACL.
                await AtomicFile.WriteAllTextAsync(
                    settings.File,
                    result.Bundle,
                    OperatingSystem.IsWindows() ? null : UnixFileMode.UserRead | UnixFileMode.UserWrite).ConfigureAwait(false);

                AnsiConsole.MarkupLine($"[green]Exported {result.Count} credential(s) to {Markup.Escape(settings.File)}.[/]");

                if (result.Skipped > 0)
                {
                    // Loud, because the archive is incomplete and the omission is
                    // otherwise invisible until a restore comes up short.
                    AnsiConsole.MarkupLine(
                        $"[yellow]Warning: {result.Skipped} credential(s) were left out because they could not be decrypted with this machine's keystore. The archive is incomplete — run 'accounts list' to see which.[/]");
                }

                AnsiConsole.MarkupLine("[grey]The archive holds every secret, protected only by the passphrase. Keep it and the passphrase safe.[/]");
                return 0;
            }
            catch (Exception ex)
            {
                CommandErrorReporter.Report(ex, "Error exporting credentials", settings.Verbose);
                return 1;
            }
        }

        private static async Task<string?> ResolveExportPassphraseAsync(Settings settings, CancellationToken cancellationToken)
        {
            if (!string.IsNullOrEmpty(settings.PassphraseEnv))
            {
                var value = Environment.GetEnvironmentVariable(settings.PassphraseEnv);
                if (string.IsNullOrEmpty(value))
                {
                    AnsiConsole.MarkupLine($"[red]Environment variable '{Markup.Escape(settings.PassphraseEnv)}' is not set or is empty.[/]");
                    return null;
                }

                return value;
            }

            var passphrase = await AnsiConsole.PromptAsync(
                new TextPrompt<string>("Enter a [green]passphrase[/] to protect the archive:")
                    .Secret()
                    .ValidationErrorMessage("[red]Passphrase cannot be empty[/]")
                    .Validate(p => !string.IsNullOrEmpty(p)), cancellationToken).ConfigureAwait(false);

            var confirm = await AnsiConsole.PromptAsync(
                new TextPrompt<string>("[green]Confirm[/] passphrase:").Secret(), cancellationToken).ConfigureAwait(false);

            if (!string.Equals(passphrase, confirm, StringComparison.Ordinal))
            {
                AnsiConsole.MarkupLine("[red]Passphrases did not match.[/]");
                return null;
            }

            return passphrase;
        }

        /// <summary>CLI settings for <c>accounts export</c>.</summary>
        public sealed class Settings : AccountsCommandSettings
        {
            /// <summary>Path the encrypted archive is written to.</summary>
            [CommandArgument(0, "<FILE>")]
            [Description("Path to write the encrypted archive to")]
            public string File { get; set; } = string.Empty;

            /// <summary>
            /// Name of an environment variable to read the passphrase from
            /// instead of prompting. Useful for scripts and CI.
            /// </summary>
            [CommandOption("--passphrase-env")]
            [Description("Read the passphrase from this environment variable instead of prompting")]
            public string? PassphraseEnv { get; set; }

            /// <summary>Overwrite the target file if it already exists.</summary>
            [CommandOption("-f|--force")]
            [Description("Overwrite the target file if it exists")]
            public bool Force { get; set; }
        }
    }
}

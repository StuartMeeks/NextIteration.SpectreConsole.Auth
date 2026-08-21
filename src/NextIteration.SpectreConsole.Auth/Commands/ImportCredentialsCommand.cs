using System.ComponentModel;

using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Portability;

using Spectre.Console;
using Spectre.Console.Cli;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Spectre.Console command for the <c>accounts import</c> branch. Reads a
    /// passphrase-encrypted archive produced by
    /// <see cref="ExportCredentialsCommand"/> and restores its credentials into
    /// the local store, re-encrypting each under this machine's backend.
    /// </summary>
    /// <remarks>DI constructor.</remarks>
    public sealed class ImportCredentialsCommand(ICredentialManager credentialManager) : AsyncCommand<ImportCredentialsCommand.Settings>
    {
        private readonly ICredentialManager _credentialManager = credentialManager;

        /// <inheritdoc />
        protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (!File.Exists(settings.File))
                {
                    AnsiConsole.MarkupLine($"[red]File not found: {Markup.Escape(settings.File)}[/]");
                    return 1;
                }

                if (!TryResolveConflictMode(settings.OnConflict, out var forcedResolution))
                {
                    AnsiConsole.MarkupLine($"[red]Invalid --on-conflict value '{Markup.Escape(settings.OnConflict!)}'. Use 'skip' or 'overwrite'.[/]");
                    return 1;
                }

                var passphrase = await ResolveImportPassphraseAsync(settings, cancellationToken).ConfigureAwait(false);
                if (passphrase is null)
                {
                    return 1;
                }

                var bundle = await File.ReadAllTextAsync(settings.File, cancellationToken).ConfigureAwait(false);

                var resolver = BuildConflictResolver(settings.OnConflict, forcedResolution);

                var service = new CredentialPortabilityService(_credentialManager);
                var result = await service.ImportAsync(bundle, passphrase, resolver).ConfigureAwait(false);

                AnsiConsole.MarkupLine(
                    $"[green]Import complete:[/] {result.Added} added, {result.Overwritten} overwritten, {result.Skipped} skipped.");
                return 0;
            }
            catch (Exception ex)
            {
                CommandErrorReporter.Report(ex, "Error importing credentials", settings.Verbose);
                return 1;
            }
        }

        private static async Task<string?> ResolveImportPassphraseAsync(Settings settings, CancellationToken cancellationToken)
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

            return await AnsiConsole.PromptAsync(
                new TextPrompt<string>("Enter the archive [green]passphrase[/]:")
                    .Secret()
                    .ValidationErrorMessage("[red]Passphrase cannot be empty[/]")
                    .Validate(p => !string.IsNullOrEmpty(p)), cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Maps the <c>--on-conflict</c> value to a fixed resolution.
        /// Returns <see langword="false"/> only when the value is present but
        /// unrecognised; a null/empty value is valid (interactive / default).
        /// </summary>
        private static bool TryResolveConflictMode(string? onConflict, out ConflictResolution resolution)
        {
            resolution = ConflictResolution.Skip;
            if (string.IsNullOrEmpty(onConflict))
            {
                return true;
            }

            if (string.Equals(onConflict, "skip", StringComparison.OrdinalIgnoreCase))
            {
                resolution = ConflictResolution.Skip;
                return true;
            }

            if (string.Equals(onConflict, "overwrite", StringComparison.OrdinalIgnoreCase))
            {
                resolution = ConflictResolution.Overwrite;
                return true;
            }

            return false;
        }

        private static Func<CredentialExport, CredentialExport, ConflictResolution> BuildConflictResolver(
            string? onConflict, ConflictResolution forcedResolution)
        {
            // An explicit --on-conflict pins the decision for every collision.
            if (!string.IsNullOrEmpty(onConflict))
            {
                return (_, _) => forcedResolution;
            }

            // No flag: prompt per conflict when we have an interactive terminal,
            // otherwise fall back to the safe default (skip) so scripted runs
            // don't hang on a prompt.
            if (!AnsiConsole.Profile.Capabilities.Interactive)
            {
                return (_, _) => ConflictResolution.Skip;
            }

            return (incoming, _) => AnsiConsole.Confirm(
                $"Credential '{Markup.Escape(incoming.AccountName)}' ({Markup.Escape(incoming.ProviderName)}/{Markup.Escape(incoming.Environment)}) already exists. Overwrite?",
                defaultValue: false)
                    ? ConflictResolution.Overwrite
                    : ConflictResolution.Skip;
        }

        /// <summary>CLI settings for <c>accounts import</c>.</summary>
        public sealed class Settings : AccountsCommandSettings
        {
            /// <summary>Path to the encrypted archive to import.</summary>
            [CommandArgument(0, "<FILE>")]
            [Description("Path to the encrypted archive to import")]
            public string File { get; set; } = string.Empty;

            /// <summary>
            /// Name of an environment variable to read the passphrase from
            /// instead of prompting. Useful for scripts and CI.
            /// </summary>
            [CommandOption("--passphrase-env")]
            [Description("Read the passphrase from this environment variable instead of prompting")]
            public string? PassphraseEnv { get; set; }

            /// <summary>
            /// How to resolve a credential that already exists (matched on
            /// provider, account name, and environment): <c>skip</c> or
            /// <c>overwrite</c>. When omitted, an interactive terminal is
            /// prompted per conflict; a non-interactive run defaults to
            /// <c>skip</c>.
            /// </summary>
            [CommandOption("--on-conflict")]
            [Description("How to resolve existing credentials: skip or overwrite (default: prompt)")]
            public string? OnConflict { get; set; }
        }
    }
}

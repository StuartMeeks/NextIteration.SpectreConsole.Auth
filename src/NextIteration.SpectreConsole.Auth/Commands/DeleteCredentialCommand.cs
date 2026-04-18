using Spectre.Console;
using System.ComponentModel;

using NextIteration.SpectreConsole.Auth.Persistence;
using Spectre.Console.Cli;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Spectre.Console command for the <c>accounts delete</c> branch.
    /// Permanently removes a credential and clears any selection that
    /// pointed to it.
    /// </summary>
    /// <remarks>DI constructor.</remarks>
    public sealed class DeleteCredentialCommand(ICredentialManager credentialManager) : AsyncCommand<DeleteCredentialCommand.Settings>
    {
        private readonly ICredentialManager _credentialManager = credentialManager;

        /// <inheritdoc />
        protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                string accountId;

                if (!string.IsNullOrWhiteSpace(settings.AccountId))
                {
                    accountId = settings.AccountId;
                }
                else
                {
                    // Interactive selection
                    var providers = await _credentialManager.GetProviderNamesAsync().ConfigureAwait(false);
                    if (!providers.Any())
                    {
                        AnsiConsole.MarkupLine("[yellow]No credentials found.[/]");
                        return 0;
                    }

                    var allCredentials = new List<CredentialSummary>();
                    foreach (var provider in providers)
                    {
                        var credentials = await _credentialManager.ListCredentialsAsync(provider).ConfigureAwait(false);
                        allCredentials.AddRange(credentials);
                    }

                    if (allCredentials.Count == 0)
                    {
                        AnsiConsole.MarkupLine("[yellow]No credentials found.[/]");
                        return 0;
                    }

                    var choices = allCredentials.Select(c =>
                        $"{c.AccountName} ({c.ProviderName} - {c.AccountId[..8]}...").ToArray();

                    var selectedChoice = await AnsiConsole.PromptAsync(
                        new SelectionPrompt<string>()
                            .Title("Select credential to [red]delete[/]:")
                            .AddChoices(choices), cancellationToken).ConfigureAwait(false);

                    var selectedIndex = Array.IndexOf(choices, selectedChoice);
                    accountId = allCredentials[selectedIndex].AccountId;
                }

                // Confirm deletion
                if (!settings.Force && !await AnsiConsole.ConfirmAsync($"Are you sure you want to delete credential '{accountId[..8]}...'?", cancellationToken: cancellationToken).ConfigureAwait(false))
                {
                    AnsiConsole.MarkupLine("[yellow]Deletion cancelled.[/]");
                    return 0;
                }

                var success = await _credentialManager.DeleteCredentialAsync(accountId).ConfigureAwait(false);

                if (success)
                {
                    AnsiConsole.MarkupLine("[green]Credential deleted successfully.[/]");
                    return 0;
                }
                else
                {
                    AnsiConsole.MarkupLine("[red]Credential not found.[/]");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                CommandErrorReporter.Report(ex, "Error deleting credential", settings.Verbose);
                return 1;
            }
        }

        /// <summary>CLI settings for <c>accounts delete</c>.</summary>
        public sealed class Settings : AccountsCommandSettings
        {
            /// <summary>
            /// ID of the credential to delete. If omitted, the user is
            /// prompted to pick from an interactive list.
            /// </summary>
            [CommandArgument(0, "[ACCOUNT_ID]")]
            [Description("The ID of the credential to delete")]
            public string? AccountId { get; set; }

            /// <summary>
            /// Skip the confirmation prompt. Useful in scripts.
            /// </summary>
            [CommandOption("-f|--force")]
            [Description("Force deletion without confirmation")]
            public bool Force { get; set; }
        }
    }
}

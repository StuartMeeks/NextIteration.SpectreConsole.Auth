using Spectre.Console;
using System.ComponentModel;

using NextIteration.SpectreConsole.Auth.Persistence;
using Spectre.Console.Cli;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Spectre.Console command for the <c>accounts select</c> branch. Marks
    /// a credential as the active one for its provider — subsequent calls
    /// to <c>IAuthenticationService.AuthenticateAsync()</c> will use this
    /// credential.
    /// </summary>
    /// <remarks>DI constructor.</remarks>
    public sealed class SelectCredentialCommand(ICredentialManager credentialManager) : AsyncCommand<SelectCredentialCommand.Settings>
    {
        private readonly ICredentialManager _credentialManager = credentialManager;

        /// <inheritdoc />
        public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
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
                        $"{c.AccountName} ({c.ProviderName} - {c.AccountId[..8]}... {(c.IsSelected ? "[green](selected)[/]" : "")}").ToArray();

                    var selectedChoice = await AnsiConsole.PromptAsync(new SelectionPrompt<string>()
                            .Title("Select credential to [green]activate[/]:")
                            .AddChoices(choices), cancellationToken).ConfigureAwait(false);

                    var selectedIndex = Array.IndexOf(choices, selectedChoice);
                    accountId = allCredentials[selectedIndex].AccountId;
                }

                var success = await _credentialManager.SelectCredentialAsync(accountId).ConfigureAwait(false);

                if (success)
                {
                    AnsiConsole.MarkupLine("[green]Credential selected successfully.[/]");
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
                CommandErrorReporter.Report(ex, "Error selecting credential", settings.Verbose);
                return 1;
            }
        }

        /// <summary>CLI settings for <c>accounts select</c>.</summary>
        public sealed class Settings : AccountsCommandSettings
        {
            /// <summary>
            /// ID of the credential to activate. If omitted, the user is
            /// prompted to pick from an interactive list.
            /// </summary>
            [CommandArgument(0, "[ACCOUNT_ID]")]
            [Description("The ID of the credential to select")]
            public string? AccountId { get; set; }
        }
    }
}

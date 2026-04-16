using System.ComponentModel;

using Spectre.Console.Auth.Persistence;
using Spectre.Console.Cli;

namespace Spectre.Console.Auth.Commands
{
    /// <summary>
    /// Spectre.Console command for the <c>accounts add</c> branch. Prompts
    /// the user for a provider, an account name and provider-specific
    /// credential fields (via the registered <see cref="ICredentialCollector"/>)
    /// and persists the result through <see cref="ICredentialManager"/>.
    /// </summary>
    /// <remarks>DI constructor.</remarks>
    public sealed class AddCredentialCommand(
        ICredentialManager credentialManager,
        IEnumerable<ICredentialCollector> collectors) : AsyncCommand<AddCredentialCommand.Settings>
    {
        private readonly ICredentialManager _credentialManager = credentialManager;
        private readonly IReadOnlyDictionary<string, ICredentialCollector> _collectorsByProvider = collectors.ToDictionary(
                c => c.ProviderName,
                StringComparer.OrdinalIgnoreCase);

        /// <summary>CLI settings for <c>accounts add</c>.</summary>
        public sealed class Settings : CommandSettings
        {
            /// <summary>
            /// Provider to add a credential for. If omitted, the user is
            /// prompted to select from the registered providers.
            /// </summary>
            [CommandOption("-p|--provider")]
            [Description("The credential provider")]
            public string? Provider { get; set; }

            /// <summary>
            /// Display name for the new credential. If omitted, the user is
            /// prompted for one.
            /// </summary>
            [CommandOption("-n|--name")]
            [Description("The account name")]
            public string? AccountName { get; set; }
        }

        /// <inheritdoc />
        public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (_collectorsByProvider.Count == 0)
                {
                    AnsiConsole.MarkupLine("[red]No credential providers are registered. Register at least one ICredentialCollector in DI.[/]");
                    return 1;
                }

                // Prompt for provider if not specified
                if (string.IsNullOrWhiteSpace(settings.Provider))
                {
                    settings.Provider = await AnsiConsole.PromptAsync(new SelectionPrompt<string>()
                            .Title("Select credential [green]provider[/]:")
                            .AddChoices(_collectorsByProvider.Keys.OrderBy(k => k)), cancellationToken).ConfigureAwait(false);
                }

                if (!_collectorsByProvider.TryGetValue(settings.Provider, out var collector))
                {
                    AnsiConsole.MarkupLine($"[red]Unknown provider: {settings.Provider}[/]");
                    return 1;
                }

                // Prompt for account name if not specified
                if (string.IsNullOrWhiteSpace(settings.AccountName))
                {
                    settings.AccountName = await AnsiConsole.PromptAsync(new TextPrompt<string>("Enter account [green]name[/]:")
                            .PromptStyle("green")
                            .ValidationErrorMessage("[red]Account name cannot be empty[/]")
                            .Validate(name => !string.IsNullOrWhiteSpace(name)), cancellationToken).ConfigureAwait(false);
                }

                var (credentialData, environment) = await collector.CollectAsync().ConfigureAwait(false);

                var accountId = await _credentialManager.AddCredentialAsync(
                    collector.ProviderName,
                    settings.AccountName,
                    environment,
                    credentialData).ConfigureAwait(false);

                AnsiConsole.MarkupLine($"[green]Successfully added credential with ID: {accountId}[/]");

                // Ask if user wants to select this credential as active
                if (await AnsiConsole.ConfirmAsync("Do you want to set this as the active credential for this environment?", cancellationToken: cancellationToken).ConfigureAwait(false))
                {
                    _ = await _credentialManager.SelectCredentialAsync(accountId).ConfigureAwait(false);
                    AnsiConsole.MarkupLine("[green]Credential selected as active.[/]");
                }

                return 0;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error adding credential: {ex.Message}[/]");
                return 1;
            }
        }
    }
}

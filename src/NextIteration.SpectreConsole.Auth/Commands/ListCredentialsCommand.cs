using Spectre.Console;
using System.ComponentModel;

using NextIteration.SpectreConsole.Auth.Persistence;
using Spectre.Console.Cli;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Spectre.Console command for the <c>accounts list</c> branch. Renders
    /// stored credentials grouped by provider, with provider-specific
    /// columns supplied by registered <see cref="ICredentialSummaryProvider"/>
    /// implementations.
    /// </summary>
    /// <remarks>DI constructor.</remarks>
    public sealed class ListCredentialsCommand(ICredentialManager credentialManager) : AsyncCommand<ListCredentialsCommand.Settings>
    {
        private readonly ICredentialManager _credentialManager = credentialManager;

        private const string _iconCheck = "\u2713"; // ✓
        private const string _iconCross = "\u2717"; // ✗

        /// <summary>CLI settings for <c>accounts list</c>.</summary>
        public sealed class Settings : AccountsCommandSettings
        {
            /// <summary>
            /// Restricts the output to a single provider. When omitted, a
            /// table is rendered per provider.
            /// </summary>
            [CommandOption("-p|--provider")]
            [Description("Filter by credential provider")]
            public string? Provider { get; set; }
        }

        /// <inheritdoc />
        protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(settings.Provider))
                {
                    var providers = await _credentialManager.GetProviderNamesAsync().ConfigureAwait(false);

                    if (!providers.Any())
                    {
                        AnsiConsole.MarkupLine("[yellow]No credentials found.[/]");
                        return 0;
                    }

                    foreach (var provider in providers)
                    {
                        await DisplayCredentialsForProvider(provider).ConfigureAwait(false);
                        AnsiConsole.WriteLine();
                    }
                }
                else
                {
                    await DisplayCredentialsForProvider(settings.Provider).ConfigureAwait(false);
                }

                return 0;
            }
            catch (Exception ex)
            {
                CommandErrorReporter.Report(ex, "Error listing credentials", settings.Verbose);
                return 1;
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>")]
        private async Task DisplayCredentialsForProvider(string provider)
        {
            var credentials = (await _credentialManager.ListCredentialsAsync(provider).ConfigureAwait(false)).ToList();

            if (credentials.Count == 0)
            {
                AnsiConsole.MarkupLine($"[yellow]No credentials found for provider '{provider}'.[/]");
                return;
            }

            // Union of display-field keys across this provider's credentials,
            // preserving first-seen order so columns render in the order the
            // summary provider intended.
            var displayFieldKeys = new List<string>();
            var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var credential in credentials)
            {
                foreach (var kvp in credential.DisplayFields)
                {
                    if (seenKeys.Add(kvp.Key))
                    {
                        displayFieldKeys.Add(kvp.Key);
                    }
                }
            }

            AnsiConsole.MarkupLine($"[bold]{provider}[/]");

            var table = new Table();
            _ = table.AddColumn("ID");
            _ = table.AddColumn("Name");
            _ = table.AddColumn("Environment");
            foreach (var key in displayFieldKeys)
            {
                _ = table.AddColumn(key);
            }
            _ = table.AddColumn("Created");
            _ = table.AddColumn("Active");

            foreach (var credential in credentials)
            {
                var row = new List<string>
                {
                    credential.AccountId[..8] + "...",
                    credential.AccountName,
                    credential.Environment,
                };

                foreach (var key in displayFieldKeys)
                {
                    var value = credential.DisplayFields
                        .FirstOrDefault(kvp => string.Equals(kvp.Key, key, StringComparison.OrdinalIgnoreCase));
                    row.Add(value.Value ?? string.Empty);
                }

                row.Add(credential.CreatedAt.ToString("yyyy-MM-dd HH:mm"));
                row.Add(credential.IsSelected ? $"[green]{_iconCheck}[/]" : $"[gray]{_iconCross}[/]");

                _ = table.AddRow([.. row]);
            }

            _ = table.Expand();

            AnsiConsole.Write(table);
        }
    }
}

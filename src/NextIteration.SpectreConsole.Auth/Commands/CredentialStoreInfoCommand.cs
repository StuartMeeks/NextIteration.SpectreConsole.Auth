using NextIteration.SpectreConsole.Auth.Persistence;

using Spectre.Console;
using Spectre.Console.Cli;

namespace NextIteration.SpectreConsole.Auth.Commands
{
    /// <summary>
    /// Spectre.Console command for <c>accounts info</c>. Shows where and how credentials
    /// are stored: the backend, the on-disk paths for the file backend, the encryption in
    /// use, and whether the store is bound to a secret.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The output describes the <see cref="ICredentialManager"/> that DI actually resolved,
    /// so it also answers "is my custom <c>ICredentialEncryption</c> really in use?".
    /// </para>
    /// <para>
    /// It never decrypts a credential or queries an OS secret store, so it is safe to run on
    /// a locked keychain and cannot prompt. Secret values, including
    /// <see cref="CredentialStoreOptions.AdditionalEntropy"/>, are reported only as present
    /// or absent.
    /// </para>
    /// <para>DI constructor.</para>
    /// </remarks>
    public sealed class CredentialStoreInfoCommand(ICredentialManager credentialManager) : Command<AccountsCommandSettings>
    {
        private readonly ICredentialManager _credentialManager = credentialManager;

        /// <inheritdoc />
        public override int Execute(CommandContext context, AccountsCommandSettings settings, CancellationToken cancellationToken)
        {
            try
            {
                var facts = CredentialStoreDescriber.Describe(_credentialManager);
                var labelWidth = facts.Max(f => f.Label.Length);

                foreach (var fact in facts)
                {
                    // The label goes through Spectre for styling, but the value is written
                    // raw: Spectre hard-wraps anything wider than the console, splitting a
                    // long path with real newlines so it no longer copy-pastes. Left to the
                    // terminal, an over-long line soft-wraps and copies intact.
                    AnsiConsole.Markup($"[bold]{Markup.Escape(fact.Label.PadRight(labelWidth))}[/]  ");
                    AnsiConsole.Profile.Out.Writer.WriteLine(fact.Value);
                }

                var warnings = facts.Where(f => f.Warning is not null).ToList();
                if (warnings.Count > 0)
                {
                    AnsiConsole.WriteLine();
                    foreach (var fact in warnings)
                    {
                        AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(fact.Warning!)}[/]");
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                CommandErrorReporter.Report(ex, "Error describing the credential store", settings.Verbose);
                return 1;
            }
        }
    }
}

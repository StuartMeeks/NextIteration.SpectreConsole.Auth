using Next.SpectreConsole.Auth.Commands;
using Spectre.Console.Cli;

namespace Next.SpectreConsole.Auth
{
    /// <summary>
    /// Spectre.Console.Cli configurator extensions for registering the
    /// credential-management command branch in a CLI.
    /// </summary>
    public static class CommandConfiguratorExtensions
    {
        /// <summary>
        /// Registers the <c>accounts</c> branch of credential-management commands
        /// (<c>add</c>, <c>list</c>, <c>select</c>, <c>delete</c>).
        /// </summary>
        public static IConfigurator AddAccountsBranch(this IConfigurator configurator)
        {
            configurator.AddBranch("accounts", accounts =>
            {
                accounts.SetDescription("Credential management commands");

                accounts.AddCommand<AddCredentialCommand>("add")
                    .WithDescription("Add a new credential")
                    .WithExample("accounts", "add", "--provider", "Adobe", "--name", "main-account");

                accounts.AddCommand<ListCredentialsCommand>("list")
                    .WithDescription("List credentials")
                    .WithExample("accounts", "list")
                    .WithExample("accounts", "list", "--provider", "Adobe");

                accounts.AddCommand<DeleteCredentialCommand>("delete")
                    .WithDescription("Delete a credential")
                    .WithExample("accounts", "delete", "12345678-1234-1234-1234-123456789012")
                    .WithExample("accounts", "delete", "--force");

                accounts.AddCommand<SelectCredentialCommand>("select")
                    .WithDescription("Select an active credential")
                    .WithExample("accounts", "select", "12345678-1234-1234-1234-123456789012")
                    .WithExample("accounts", "select");
            });

            return configurator;
        }
    }
}

using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Auth.Encryption;
using Spectre.Console.Auth.Persistence;

namespace Spectre.Console.Auth
{
    /// <summary>
    /// DI extensions for registering the <c>Spectre.Console.Auth</c>
    /// credential store.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the credential encryption and file-based credential manager.
        /// Consumers must still register their provider-specific authentication services
        /// and <c>ICredentialCollector</c> implementations separately.
        /// </summary>
        public static IServiceCollection AddCredentialStore(
            this IServiceCollection services,
            Action<CredentialStoreOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);

            var options = new CredentialStoreOptions();
            configure(options);

            if (string.IsNullOrWhiteSpace(options.CredentialsDirectory))
            {
                throw new InvalidOperationException(
                    $"{nameof(CredentialStoreOptions)}.{nameof(CredentialStoreOptions.CredentialsDirectory)} must be set.");
            }

            services.AddSingleton(options);
            services.AddSingleton<ICredentialEncryption>(_ => CredentialEncryptionFactory.Create(options.CredentialsDirectory));
            services.AddSingleton<ICredentialManager>(sp =>
                new FileCredentialManager(
                    sp.GetRequiredService<ICredentialEncryption>(),
                    options.CredentialsDirectory,
                    sp.GetServices<ICredentialSummaryProvider>()));

            return services;
        }
    }
}

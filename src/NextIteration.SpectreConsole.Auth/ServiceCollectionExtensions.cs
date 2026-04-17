using Microsoft.Extensions.DependencyInjection;

using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Encryption;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Persistence.Keychain;
using NextIteration.SpectreConsole.Auth.Persistence.Libsecret;

namespace NextIteration.SpectreConsole.Auth
{
    /// <summary>
    /// DI extensions for registering the <c>NextIteration.SpectreConsole.Auth</c>
    /// credential store.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the credential store: by default the file-based backend
        /// rooted at <see cref="CredentialStoreOptions.CredentialsDirectory"/>,
        /// or — when <see cref="CredentialStoreOptions.UseKeychain"/> is set on
        /// macOS — the Keychain backend scoped by
        /// <see cref="CredentialStoreOptions.KeychainAppIdentifier"/>.
        /// Consumers must still register their provider-specific authentication
        /// services and <c>ICredentialCollector</c> implementations separately.
        /// </summary>
        public static IServiceCollection AddCredentialStore(
            this IServiceCollection services,
            Action<CredentialStoreOptions> configure)
        {
            ArgumentNullException.ThrowIfNull(configure);

            var options = new CredentialStoreOptions();
            configure(options);

            services.AddSingleton(options);

            if (options.UseKeychain && options.UseKeyring)
            {
                throw new InvalidOperationException(
                    $"{nameof(CredentialStoreOptions)}: {nameof(CredentialStoreOptions.UseKeychain)} and {nameof(CredentialStoreOptions.UseKeyring)} are mutually exclusive.");
            }

            if (options.UseKeychain)
            {
                RegisterKeychainBackend(services, options);
            }
            else if (options.UseKeyring)
            {
                RegisterKeyringBackend(services, options);
            }
            else
            {
                RegisterFileBackend(services, options);
            }

            return services;
        }

        private static void RegisterFileBackend(IServiceCollection services, CredentialStoreOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.CredentialsDirectory))
            {
                throw new InvalidOperationException(
                    $"{nameof(CredentialStoreOptions)}.{nameof(CredentialStoreOptions.CredentialsDirectory)} must be set when using the file-based backend.");
            }

            services.AddSingleton<ICredentialEncryption>(_ => CredentialEncryptionFactory.Create(options.CredentialsDirectory, options.AdditionalEntropy));
            services.AddSingleton<ICredentialManager>(sp =>
                new FileCredentialManager(
                    sp.GetRequiredService<ICredentialEncryption>(),
                    options.CredentialsDirectory,
                    sp.GetServices<ICredentialSummaryProvider>()));
        }

        private static void RegisterKeychainBackend(IServiceCollection services, CredentialStoreOptions options)
        {
            if (!OperatingSystem.IsMacOS())
            {
                throw new PlatformNotSupportedException(
                    $"{nameof(CredentialStoreOptions)}.{nameof(CredentialStoreOptions.UseKeychain)} is only supported on macOS.");
            }

            if (string.IsNullOrWhiteSpace(options.KeychainAppIdentifier))
            {
                throw new InvalidOperationException(
                    $"{nameof(CredentialStoreOptions)}.{nameof(CredentialStoreOptions.KeychainAppIdentifier)} must be set when using the Keychain backend.");
            }

            services.AddSingleton<ICredentialManager>(sp => BuildKeychainManager(options, sp));
        }

        // Factored into its own method so the [SupportedOSPlatform("macos")]
        // annotation on KeychainCredentialManager is honoured and the
        // analyzer doesn't warn on the non-macOS code path (which is guarded
        // by the RegisterKeychainBackend check above).
        private static KeychainCredentialManager BuildKeychainManager(CredentialStoreOptions options, IServiceProvider sp)
        {
            if (!OperatingSystem.IsMacOS())
            {
                throw new PlatformNotSupportedException("KeychainCredentialManager is macOS-only.");
            }
            return new KeychainCredentialManager(
                options.KeychainAppIdentifier,
                sp.GetServices<ICredentialSummaryProvider>());
        }

        private static void RegisterKeyringBackend(IServiceCollection services, CredentialStoreOptions options)
        {
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException(
                    $"{nameof(CredentialStoreOptions)}.{nameof(CredentialStoreOptions.UseKeyring)} is only supported on Linux.");
            }

            if (string.IsNullOrWhiteSpace(options.KeyringAppIdentifier))
            {
                throw new InvalidOperationException(
                    $"{nameof(CredentialStoreOptions)}.{nameof(CredentialStoreOptions.KeyringAppIdentifier)} must be set when using the libsecret backend.");
            }

            services.AddSingleton<ICredentialManager>(sp => BuildKeyringManager(options, sp));
        }

        private static LibsecretCredentialManager BuildKeyringManager(CredentialStoreOptions options, IServiceProvider sp)
        {
            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("LibsecretCredentialManager is Linux-only.");
            }
            return new LibsecretCredentialManager(
                options.KeyringAppIdentifier,
                sp.GetServices<ICredentialSummaryProvider>(),
                options.KeyringCollection);
        }
    }
}

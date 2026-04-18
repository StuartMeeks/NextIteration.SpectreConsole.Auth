# NextIteration.SpectreConsole.Auth

[![NuGet](https://img.shields.io/nuget/v/NextIteration.SpectreConsole.Auth.svg)](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth/)
[![Downloads](https://img.shields.io/nuget/dt/NextIteration.SpectreConsole.Auth.svg)](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/)
[![CI](https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/actions/workflows/ci.yml/badge.svg)](https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/actions/workflows/ci.yml)

Encrypted credential storage and ready-made `accounts` commands for CLI tools built on [Spectre.Console](https://spectreconsole.net/).

Stop copy-pasting the same `~/.app/creds.json` + AES boilerplate into every CLI you build. Drop this package in, register your provider, and `my-cli accounts add` / `list` / `select` / `delete` just works — with AES-GCM encryption, atomic writes, hardened filesystem permissions, and a pluggable model for any provider your tool talks to.

---

## Features

- **`accounts` command branch** — `add`, `list`, `select`, `delete` wired into your existing `CommandApp` with a single call.
- **AES-GCM authenticated encryption** — tamper detection on every read, no padding-oracle surface.
- **Hardened storage** — Unix mode `0600` on credential files, Windows ACL stripped of inheritance so only the current user + SYSTEM can read the credentials directory.
- **Atomic writes** — crash mid-write never leaves a half-written credential or keystore on disk.
- **Provider-aware list rendering** — your `accounts list` output shows provider-specific columns (masked token, base URL, actor, whatever you need) instead of a flat table.
- **Extensible** — bring your own provider by implementing three small interfaces. Adobe, Airtable, and SoftwareOne provider packages ship separately.
- **DPAPI option on Windows** — swap the default cross-platform backend for Windows DPAPI with one factory call.
- **Zero compiler warnings, fully documented public surface** — `<GenerateDocumentationFile>` on, analyzers on, `TreatWarningsAsErrors` on.

---

## Install

```shell
dotnet add package NextIteration.SpectreConsole.Auth
```

Pair it with one or more provider packages (or write your own — see [Extending](#extending-with-a-custom-provider)):

```shell
dotnet add package NextIteration.SpectreConsole.Auth.Providers.Adobe
dotnet add package NextIteration.SpectreConsole.Auth.Providers.Airtable
dotnet add package NextIteration.SpectreConsole.Auth.Providers.SoftwareOne
```

Targets `net10.0`.

---

## Quick start

Inside your `Program.cs` — assuming you already have a DI container and a Spectre.Console.Cli `CommandApp` wired up:

```csharp
using NextIteration.SpectreConsole.Auth;
using NextIteration.SpectreConsole.Auth.Providers.Adobe;

// 1. Register the credential store, pointing at a per-app directory
services.AddCredentialStore(opts =>
{
    opts.CredentialsDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".my-cli", "credentials");
});

// 2. Register the provider(s) you care about
services.AddAdobeAuthProvider();

// 3. Hook the `accounts` branch into your command configurator
app.Configure(config =>
{
    config.AddAccountsBranch();
    // ... your other commands
});
```

That's it. Running your CLI now:

```console
$ my-cli accounts add --provider Adobe --name prod
Enter IMS URL [https://ims-na1.adobelogin.com/]:
Enter API Key: ********
Enter Client Secret: ********
Enter Base URL [https://partners.adobe.io/]:
Select environment:
> Production
  Sandbox
Successfully added credential with ID: 8f4e...
Do you want to set this as the active credential for this environment? [y/N]: y
```

And from inside any of your command handlers:

```csharp
public sealed class SyncCommand(AdobeAuthenticationService auth) : AsyncCommand
{
    public override async Task<int> ExecuteAsync(CommandContext context)
    {
        var token = await auth.AuthenticateAsync();
        // use token.GetAuthorizationHeader() on outgoing requests
        return 0;
    }
}
```

---

## The `accounts` branch

| Command | Description |
|---|---|
| `accounts add` | Interactive: pick a provider, name the credential, fill in provider-specific fields. |
| `accounts list` | Table of stored credentials, grouped by provider, with provider-specific columns (masked tokens, URLs, etc.). |
| `accounts select [id]` | Mark one credential as the active one for its provider. Subsequent `AuthenticateAsync()` calls use it. |
| `accounts delete [id] [--force]` | Remove a credential. Clears the selection if it pointed at the deleted entry. |

Every command accepts `-v` / `--verbose` for full stack-trace output when something goes wrong.

---

## Security model

Credentials are encrypted with **AES-GCM** (authenticated — tampering is detected on decrypt). The data-encryption key is itself encrypted and stored in a `.keystore` file inside your credentials directory. The key-encryption key (KEK) is derived from machine + user identifiers via PBKDF2-HMAC-SHA256 (600,000 iterations).

**What this protects against:**

- Other users on the same machine reading your credentials (filesystem permissions on the credentials directory enforce this).
- A casual attacker who ends up with a copy of the `.keystore` file but lacks knowledge of the originating machine and user.
- Undetected tampering of credential files (AES-GCM's authentication tag refuses decryption on any modification).

**What it does *not* protect against** (in default mode):

- A local attacker who has read access to the credentials directory **and** knows the machine hostname + username — the KEK is deterministic given those inputs. Close this gap either by supplying `AdditionalEntropy` (see below) or by using DPAPI / a platform keychain.
- A compromised running process: once your CLI has decrypted a credential in memory, it's in memory.

**Hardening with `AdditionalEntropy`:**

The default KEK is derived purely from machine state, so anyone who copies the `.keystore` file plus the machine's hostname/username can decrypt. Pass a secret into `CredentialStoreOptions.AdditionalEntropy` to close that gap:

```csharp
services.AddCredentialStore(opts =>
{
    opts.CredentialsDirectory = Path.Combine(userProfile, ".my-cli", "credentials");
    opts.AdditionalEntropy = Convert.FromHexString(
        Environment.GetEnvironmentVariable("MY_CLI_ENTROPY_HEX")
        ?? throw new InvalidOperationException("MY_CLI_ENTROPY_HEX not set"));
});
```

The entropy is mixed into the PBKDF2 password so the KEK now depends on both the machine AND this value. An attacker with the keystore file but without the entropy can't decrypt. Common sources: a per-deployment secret from env / HSM, a value from a secret manager, a user-entered passphrase.

Caveats:

- Changing the entropy value invalidates the existing keystore — decryption will fail with "integrity check" and credentials must be re-added.
- `AdditionalEntropy` is ignored when `UseKeychain` or `UseKeyring` is set (those backends don't use PBKDF2).

The real security boundary is the **filesystem permissions on the credentials directory**. On first creation the library sets:

- **Unix:** mode `0700` on the directory, `0600` on every file.
- **Windows:** ACL inheritance disabled, explicit `FullControl` for the current user and `SYSTEM` only.

For cryptographically stronger isolation:

- **Windows:** switch to DPAPI via `CredentialEncryptionFactory.CreateDpapi()`.
- **macOS:** opt into the experimental Keychain backend — see [Advanced](#macos-keychain-backend-experimental) below.
- **Linux:** opt into the experimental libsecret backend — see [Advanced](#linux-libsecret-backend-experimental) below.

---

## Extending with a custom provider

Three interfaces to implement, one DI registration. Here's a GitHub PAT provider end-to-end:

```csharp
using System.Text.Json;
using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Credentials;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Services;
using NextIteration.SpectreConsole.Auth.Tokens;
using Spectre.Console;

// 1. The credential — what you persist on disk (encrypted).
public sealed class GitHubCredential : ICredential
{
    public static string ProviderName => "GitHub";
    public static List<string> SupportedEnvironments => ["Production"];
    public required string PersonalAccessToken { get; init; }
    public required string Environment { get; init; }
}

// 2. The token — what AuthenticateAsync returns.
public sealed class GitHubToken : IToken
{
    public required string AccessToken { get; init; }
    public bool IsExpired => false;
    public string GetAuthorizationHeader() => $"Bearer {AccessToken}";
}

// 3. The authentication service — exchanges credential for token.
public sealed class GitHubAuthenticationService(ICredentialManager manager)
    : IAuthenticationService<GitHubCredential, GitHubToken>
{
    public async Task<GitHubToken> AuthenticateAsync()
    {
        var json = await manager.GetSelectedCredentialAsync(GitHubCredential.ProviderName)
            ?? throw new InvalidOperationException("No GitHub credential selected");
        var credential = JsonSerializer.Deserialize<GitHubCredential>(json)!;
        return await AuthenticateAsync(credential);
    }

    public Task<GitHubToken> AuthenticateAsync(GitHubCredential credential) =>
        Task.FromResult(new GitHubToken { AccessToken = credential.PersonalAccessToken });

    public Task<bool> ValidateTokenAsync(GitHubToken token) =>
        Task.FromResult(!token.IsExpired);
}

// 4. The collector — prompts the user during `accounts add`.
public sealed class GitHubCredentialCollector : ICredentialCollector
{
    public string ProviderName => GitHubCredential.ProviderName;

    public async Task<(string credentialData, string environment)> CollectAsync()
    {
        var pat = await AnsiConsole.PromptAsync(
            new TextPrompt<string>("GitHub personal access token:").Secret());
        var credential = new GitHubCredential
        {
            PersonalAccessToken = pat,
            Environment = "Production",
        };
        return (JsonSerializer.Serialize(credential), credential.Environment);
    }
}

// 5. (Optional) The summary provider — columns in `accounts list`.
public sealed class GitHubCredentialSummaryProvider : ICredentialSummaryProvider
{
    public string ProviderName => GitHubCredential.ProviderName;
    public IReadOnlyList<KeyValuePair<string, string>> GetDisplayFields(string decryptedJson)
    {
        var c = JsonSerializer.Deserialize<GitHubCredential>(decryptedJson)!;
        var masked = c.PersonalAccessToken[..4] + "..." + c.PersonalAccessToken[^4..];
        return [new("Token", masked)];
    }
}

// 6. Register in DI.
services.AddSingleton<GitHubAuthenticationService>();
services.AddSingleton<ICredentialCollector, GitHubCredentialCollector>();
services.AddSingleton<ICredentialSummaryProvider, GitHubCredentialSummaryProvider>();
```

That's everything. `my-cli accounts add` now shows `GitHub` as a provider option, stores an encrypted `GitHubCredential`, and `my-cli accounts list` renders the masked token.

See the companion [provider packages repo](https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth.Providers) for fuller examples (OAuth2 client-credentials, base-URL routing, actor-role scoping).

---

## Official provider packages

| Package | Provider | Auth style |
|---|---|---|
| [NextIteration.SpectreConsole.Auth.Providers.Adobe](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth.Providers.Adobe/) | Adobe IMS | OAuth2 client-credentials |
| [NextIteration.SpectreConsole.Auth.Providers.Airtable](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth.Providers.Airtable/) | Airtable | Personal access token (pass-through) |
| [NextIteration.SpectreConsole.Auth.Providers.SoftwareOne](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth.Providers.SoftwareOne/) | SoftwareOne | API token (pass-through, actor-scoped) |

---

## Advanced

### Linux libsecret backend (experimental)

On Linux you can opt into storing credentials directly in the user's
keyring (GNOME Keyring, KWallet's shim, any Secret Service implementation)
via libsecret. Each credential becomes a Secret Service item, visible and
manageable via Seahorse/KWalletManager.

```csharp
services.AddCredentialStore(opts =>
{
    opts.UseKeyring = true;
    opts.KeyringAppIdentifier = "com.mycompany.my-cli";
});
```

> ⚠️ **Experimental.** Requires a running Secret Service daemon — headless
> containers and SSH-only servers typically don't have one, and operations
> will throw with a clear message. Primarily validated against GNOME
> Keyring on Ubuntu. `UseKeyring = true` on non-Linux platforms throws
> `PlatformNotSupportedException` at registration time.

`UseKeyring` and `UseKeychain` are mutually exclusive — setting both throws.
The file-based backend remains the default when neither is set.

### macOS Keychain backend (experimental)

On macOS you can opt into storing credentials directly in the user's login
Keychain instead of in an encrypted file. Each credential becomes a
generic-password keychain item, visible and manageable via `Keychain
Access.app`. No `.keystore`, no AES, no file permissions — the Keychain
itself is the secret store.

```csharp
services.AddCredentialStore(opts =>
{
    opts.UseKeychain = true;
    opts.KeychainAppIdentifier = "com.mycompany.my-cli";
    // CredentialsDirectory is ignored when UseKeychain is set.
});
```

> ⚠️ **Experimental.** The Keychain backend is P/Invoked against
> `Security.framework` and exercised by a macOS CI runner, but hasn't yet
> been validated against diverse deployment environments. Opt in knowingly.
> `UseKeychain = true` on non-macOS platforms throws `PlatformNotSupportedException`
> at registration time; the file-based backend remains the default.

The `KeychainAppIdentifier` namespaces your CLI's keychain items so they
don't collide with other tools sharing the same login keychain. Use a
reverse-DNS string like `com.mycompany.my-cli`.

### Switching to DPAPI on Windows

`CredentialEncryptionFactory.Create(path)` returns the cross-platform backend by default. For DPAPI-backed storage on Windows:

```csharp
services.AddSingleton<ICredentialEncryption>(_ => CredentialEncryptionFactory.CreateDpapi());
services.AddSingleton<ICredentialManager, FileCredentialManager>();
```

### Multiple credentials per provider

You can store as many credentials per provider as you like. `accounts select` activates one at a time per provider — so `Adobe` production and `Adobe` sandbox live side-by-side, and a quick `accounts select <id>` swaps which one your auth service resolves.

### Custom encryption backend

Implement `ICredentialEncryption` and register it before calling `AddCredentialStore`. `FileCredentialManager` will pick up whatever backend is registered.

---

## Requirements

- **.NET 10.0** or later
- **Spectre.Console** 0.54+ and **Spectre.Console.Cli** 0.53+
- **Microsoft.Extensions.DependencyInjection.Abstractions** 10.0+

Everything else is transitive.

---

## Contributing

Issues and PRs welcome. The [TODO](TODO.md) tracks outstanding hardening — keystore format versioning, zero-on-dispose for caller-supplied entropy, ACL-scoped Keychain access, and KWallet validation for the libsecret backend.

When contributing code, please keep the zero-warning, fully-documented public surface. `TreatWarningsAsErrors` is on for a reason.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

---

## License

[MIT](LICENSE) © Stuart Meeks

Built for — and unaffiliated with — the excellent [Spectre.Console](https://github.com/spectreconsole/spectre.console) project.

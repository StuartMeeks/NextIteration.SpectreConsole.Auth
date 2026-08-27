# NextIteration.SpectreConsole.Auth

[![NuGet](https://img.shields.io/nuget/v/NextIteration.SpectreConsole.Auth.svg)](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth/)
[![Downloads](https://img.shields.io/nuget/dt/NextIteration.SpectreConsole.Auth.svg)](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-purple.svg)](https://dotnet.microsoft.com/)
[![CI](https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/actions/workflows/ci.yml/badge.svg)](https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/actions/workflows/ci.yml)

Encrypted credential storage and ready-made `accounts` commands for CLI tools built on [Spectre.Console](https://spectreconsole.net/).

Stop copy-pasting the same `~/.app/creds.json` + AES boilerplate into every CLI you build. Drop this package in, register your provider, and `my-cli accounts add` / `list` / `select` / `delete` just works — with AES-GCM encryption, atomic writes, hardened filesystem permissions, and a pluggable model for any provider your tool talks to.

---

## Features

- **`accounts` command branch** — `add`, `list`, `select`, `delete`, `export`, `import` wired into your existing `CommandApp` with a single call.
- **AES-GCM authenticated encryption** — tamper detection on every read, no padding-oracle surface.
- **Hardened storage** — Unix mode `0600` on credential files, Windows ACL stripped of inheritance so only the current user + SYSTEM can read the credentials directory.
- **Atomic writes** — crash mid-write never leaves a half-written credential or keystore on disk.
- **Provider-aware list rendering** — your `accounts list` output shows provider-specific columns (masked token, base URL, actor, whatever you need) instead of a flat table.
- **Extensible** — bring your own provider by implementing three small interfaces. Adobe, Airtable, and SoftwareOne provider packages ship separately.
- **DPAPI option on Windows** — swap the default cross-platform backend for Windows DPAPI with one factory call.
- **Cancellable throughout** — every `ICredentialManager` member takes a `CancellationToken`, wired down to a `GCancellable` on the libsecret backend so a prompting secret store cannot wedge your CLI.
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
dotnet add package NextIteration.SpectreConsole.Auth.Providers.GitHub
```

Targets `net8.0` and `net10.0`.

**Pair matching major versions.** Each provider package depends on this one through a
major-capped range, so `2.x` providers require `2.x` of this package and NuGet will refuse to
mix them:

| This package | Provider packages |
|---|---|
| `2.x` | `2.x` |
| `1.x` | `1.0.1`+ |

That refusal is deliberate and worth understanding. `ICredentialManager` changed shape in
2.0.0, and the providers call into it — so a `1.x` provider assembly running against `2.x` of
this package would fail at *runtime* with `MissingMethodException`. The version cap turns that
into a resolution error you read at restore time instead.

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
    protected override async Task<int> ExecuteAsync(CommandContext context, CancellationToken cancellationToken)
    {
        var token = await auth.AuthenticateAsync(cancellationToken);
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
| `accounts list` | Table of stored credentials, grouped by provider, with provider-specific columns (masked tokens, URLs, etc.). Entries whose payload cannot be read are still listed, marked `(unreadable)`, so you can see and remove them. |
| `accounts select [id]` | Mark one credential as the active one for its provider. Subsequent `AuthenticateAsync()` calls use it. |
| `accounts delete [id] [--force]` | Remove a credential. Clears the selection if it pointed at the deleted entry. |
| `accounts export <file> [--force]` | Write every credential to a single passphrase-encrypted archive. |
| `accounts import <file> [--on-conflict skip\|overwrite]` | Restore credentials from an archive into this machine's store. |

Every command accepts `-v` / `--verbose` for full stack-trace output when something goes wrong.

### Moving credentials between machines

Stored credentials are encrypted with a **machine-bound** key (the local KEK is derived from machine/user identity; the Keychain/libsecret/DPAPI backends key off the OS secret store). That means the files on disk can't simply be copied to another machine — they won't decrypt there. `accounts export` / `accounts import` solve this by re-encrypting the whole set under a passphrase you carry:

```console
# On the old machine — you'll be prompted for a passphrase (and to confirm it):
$ my-cli accounts export credentials.bundle
Exported 4 credential(s) to credentials.bundle.

# Copy credentials.bundle to the new machine, then:
$ my-cli accounts import credentials.bundle
```

- **Passphrase-only.** The archive is AES-256-GCM encrypted with a PBKDF2-derived key (600,000 iterations, random per-export salt). There is no plaintext export. For scripting, read the passphrase from an environment variable with `--passphrase-env MY_VAR` instead of being prompted. On Unix the archive file is written `0600`.
- **Conflicts.** An imported credential is matched to an existing one on *(provider, account name, environment)*. On a match you're prompted to skip or overwrite; pass `--on-conflict skip` or `--on-conflict overwrite` to decide up front (a non-interactive run with no flag skips).
- **Fidelity.** Account IDs and which credential is selected are preserved. Original creation timestamps are preserved on the file and libsecret backends; the macOS Keychain assigns its own, so imported items show a fresh timestamp there.
- **A credential that cannot be read is left out, not exported blank.** If the store holds an entry this machine's keystore can no longer decrypt — a credentials directory copied from another machine, say — `accounts export` skips it and tells you how many it skipped. The archive is then genuinely incomplete, which is why it says so: writing an empty payload instead would restore *over* a real secret at the far end. `accounts list` marks the same entries `(unreadable)` so you can see which they are.

> The archive contains **every stored secret**, protected only by your passphrase. Choose a strong one and treat the file as sensitive.

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

Two interfaces you must implement — `ICredentialCollector` and an
`IAuthenticationService<,>` — plus the credential and token types they work with, and an
optional `ICredentialSummaryProvider` for the `accounts list` columns. One DI registration.

The worked example below builds a GitHub PAT provider because it is the smallest useful one.
Note that it already ships as
[`…Providers.GitHub`](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth.Providers.GitHub/),
so take this as the pattern rather than as something you need to write:

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
    public async Task<GitHubToken> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        var json = await manager.GetSelectedCredentialAsync(GitHubCredential.ProviderName, cancellationToken)
            ?? throw new InvalidOperationException("No GitHub credential selected");
        var credential = JsonSerializer.Deserialize<GitHubCredential>(json)!;
        return await AuthenticateAsync(credential, cancellationToken);
    }

    public Task<GitHubToken> AuthenticateAsync(GitHubCredential credential, CancellationToken cancellationToken = default) =>
        Task.FromResult(new GitHubToken { AccessToken = credential.PersonalAccessToken });

    public Task<bool> ValidateTokenAsync(GitHubToken token, CancellationToken cancellationToken = default) =>
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
| [NextIteration.SpectreConsole.Auth.Providers.GitHub](https://www.nuget.org/packages/NextIteration.SpectreConsole.Auth.Providers.GitHub/) | GitHub | Personal access token (pass-through) |

---

## Advanced

### Linux libsecret backend (experimental)

On Linux you can opt into storing credentials directly in the user's GNOME
Keyring via libsecret. Each credential becomes a Secret Service item, visible
and manageable via Seahorse.

```csharp
services.AddCredentialStore(opts =>
{
    opts.UseKeyring = true;
    opts.KeyringAppIdentifier = "com.mycompany.my-cli";
});
```

> ⚠️ **Experimental.** Requires a running Secret Service daemon — headless
> containers and SSH-only servers typically don't have one. Operations then
> throw with a clear message, *unless* the daemon is present but wants to
> prompt, in which case see the KWallet note below. `UseKeyring = true` on
> non-Linux platforms throws `PlatformNotSupportedException` at registration
> time.

**Validated against GNOME Keyring only.** KWallet's Secret Service shim
(`ksecretd`) was tested and does *not* work unattended (see
[#19](https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/issues/19)):

- It does not provide the `session` collection that GNOME Keyring does, so
  `KeyringCollection = "session"` fails outright with *"No such object path
  `/org/freedesktop/secrets/aliases/session`"*.
- With the default collection it prompts to unlock the wallet. In a desktop KDE
  session a user can answer that; with no GUI the call **blocks indefinitely** —
  and cancelling does not rescue it. `ksecretd` emits the prompt's `Completed`
  signal with an `ao` payload where libsecret expects `o`, so libsecret abandons
  its prompt task *"without ever returning"* and the nested main loop never
  exits. The cancellation fires and cannot reach a task libsecret has already
  dropped, so this is an upstream incompatibility rather than something this
  backend can work around.

Treat KWallet as unsupported. Other Secret Service implementations are untested.

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

`CredentialEncryptionFactory.Create(path)` returns the cross-platform backend by default. For DPAPI-backed storage on Windows, register both services yourself instead of calling `AddCredentialStore`:

```csharp
var credentialsDirectory = Path.Combine(userProfile, ".my-cli", "credentials");

services.AddSingleton<ICredentialEncryption>(_ => CredentialEncryptionFactory.CreateDpapi());
services.AddSingleton<ICredentialManager>(sp => new FileCredentialManager(
    sp.GetRequiredService<ICredentialEncryption>(),
    credentialsDirectory,
    sp.GetServices<ICredentialSummaryProvider>()));
```

`FileCredentialManager` takes its directory as a constructor argument, so it cannot be
registered by type — `AddSingleton<ICredentialManager, FileCredentialManager>()` throws
`Unable to resolve service for type 'System.String'` at resolution time. Passing
`GetServices<ICredentialSummaryProvider>()` is what keeps your provider columns in
`accounts list`; omit it and the table falls back to the generic columns.

### Multiple credentials per provider

You can store as many credentials per provider as you like. `accounts select` activates one at a time per provider — so `Adobe` production and `Adobe` sandbox live side-by-side, and a quick `accounts select <id>` swaps which one your auth service resolves.

### Custom encryption backend

Implement `ICredentialEncryption` and register it **after** `AddCredentialStore`:

```csharp
services.AddCredentialStore(opts => { /* ... */ });
services.AddSingleton<ICredentialEncryption>(_ => new MyEncryption());   // must come second
```

Order matters and getting it wrong fails **silently**. `AddCredentialStore` registers its own
`ICredentialEncryption`, and the last registration of a service type is the one resolved — so
a custom backend registered *first* is quietly ignored and your credentials are encrypted with
the default one. There is no error to tell you, which is exactly the wrong failure mode for a
change made to strengthen encryption. Register after, and verify with
`provider.GetRequiredService<ICredentialEncryption>().GetType()` if in doubt.

---

## Requirements

- **.NET 8.0** or **.NET 10.0** (the package multi-targets `net8.0;net10.0`)
- **Spectre.Console** 0.57.2+ and **Spectre.Console.Cli** 0.55.0+
- **Microsoft.Extensions.DependencyInjection.Abstractions** — 8.0.2+ on `net8.0`,
  10.0.10+ on `net10.0`

Dependency floors are set per target framework, so a `net8.0` consumer is never dragged
off its own 8.0.x servicing line.

Everything else is transitive.

---

## Contributing

Issues and PRs welcome. Outstanding work is tracked in [GitHub issues](https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/issues); there is
none open at the time of writing.

When contributing code, please keep the zero-warning, fully-documented public surface. `TreatWarningsAsErrors` is on for a reason.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

---

## License

[MIT](LICENSE) © Stuart Meeks

Built for — and unaffiliated with — the excellent [Spectre.Console](https://github.com/spectreconsole/spectre.console) project.

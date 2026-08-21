# Changelog

All notable changes to `NextIteration.SpectreConsole.Auth` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **`accounts export` and `accounts import` — move your whole credential set between
  machines.** On-disk credential ciphertext is machine-bound (each backend keys off
  machine/user identity or an OS secret store), so the raw files can't be copied across
  machines. Export instead reads every credential *decrypted* and re-encrypts the whole
  set into a single portable archive under a **user-supplied passphrase** (AES-256-GCM
  over PBKDF2-HMAC-SHA256, 600k iterations, random per-export salt); import decrypts it and
  re-stores each credential through the normal backend path, re-protecting it under the
  destination machine's key/store. The archive holds every secret protected only by the
  passphrase, so the export command warns accordingly and writes the file `0600` on Unix.
  - Export always requires a passphrase (prompted and confirmed, or read from an env var
    via `--passphrase-env` for scripts); there is no plaintext export path.
  - Import matches an incoming credential to an existing one on
    *(provider, account name, environment)* and, on a collision, prompts per conflict for
    skip/overwrite. `--on-conflict skip|overwrite` makes it non-interactive; a
    non-interactive run with no flag defaults to `skip`.
  - AccountId and selection state are preserved on all backends; `CreatedAt` is preserved
    on the file and libsecret backends. On the macOS Keychain the creation timestamp is
    assigned by the OS, so a restored item gets a fresh one (cosmetic only).

- **`LocalFileCredentialEncryption` now zeroes key material on dispose.** The class
  implements `IDisposable` and, when disposed, `CryptographicOperations.ZeroMemory`s the
  in-memory data key and any caller-supplied entropy so a heap dump taken after shutdown
  doesn't expose them. Registered as a DI singleton (the default), this runs at container
  disposal — no consumer code change required.

### Changed

- **Adopted the revised canonical `.editorconfig`** (NextIteration.Standards §5.2). The new
  file is a deliberate allow-list of gated style rules (no blanket
  `dotnet_analyzer_diagnostic.severity`) and fixes the private-field naming rule that had
  demanded `_camelCase` for `PascalCase` constants. `EnforceCodeStyleInBuild` stays **off**
  per §1.2.1 (blocked estate-wide), so the `IDE*` rules remain advisory at build time; the
  one build-affecting change is `CS1591` moving from `silent` to `warning` (a missing XML
  doc on a public member is now a build error under `TreatWarningsAsErrors` — the public
  surface is already fully documented, so the build stays clean).

- **Cleared the open CodeQL code-quality alerts.** All genuine fixes, no suppression
  hacks:
  - Repo-wide `Path.Combine` → `Path.Join` in `src` and `tests` (resolves #24). `Path.Join`
    never treats a later segment as rooted, so it can't silently drop earlier arguments —
    defence-in-depth for the credential/keystore path construction, which is already
    input-validated.
  - Idiomatic LINQ in place of filter-style loops: `providerName.Any(...)` for the
    `ValidateProviderName` checks, `Distinct(OrdinalIgnoreCase)` for the `accounts list`
    column-key union, and `.Where(...)` / `.FirstOrDefault(predicate)` in the Keychain
    backend.
  - Narrowed the exception handling in `DpapiCredentialEncryption` and
    `LocalFileCredentialEncryption` from `catch (Exception)` to the specific types actually
    expected (`CryptographicException`, `FormatException`, `IOException`,
    `UnauthorizedAccessException`); a truly unexpected exception now propagates instead of
    being masked as a generic encrypt/decrypt failure. The deliberately-broad boundary
    catches (CLI command handlers, best-effort cleanup) are unchanged by design.

- **`TODO.md` retired; its backlog moved to GitHub issues.** Completed items shipped in
  this cycle (the flaky secret-store delete test, keystore format versioning, and
  zero-on-dispose — see above). Remaining items that need an environment or a
  NextIteration.Standards change were migrated to issues: Keychain ACL hardening (#18),
  libsecret KWallet validation (#19), macOS CI version matrix (#20), splitting the Linux
  keyring CI job (#21), and a repo-wide `Path.Combine` → `Path.Join` sweep (#24). Decision
  recorded: the macOS Keychain and Linux libsecret backends stay **opt-in** while marked
  experimental (revisit when that tag is dropped), as already documented on
  `CredentialStoreOptions.UseKeychain` / `UseKeyring`.

- **`.keystore` files now carry a format header (magic + 1-byte version).** A future
  KDF/format change can now be detected and rejected with a clear "unsupported keystore
  format version" error instead of surfacing as an opaque integrity-check failure.
  Keystores written by earlier (headerless) versions are still read; **note the reverse is
  not true** — a keystore written by this version is not readable by pre-header library
  versions. For consistency, `EncryptAsync` now lets an already-actionable
  `InvalidOperationException` (such as this one) propagate as-is rather than re-wrapping it
  as a generic encrypt failure, matching `DecryptAsync`.

- **BREAKING: `ICredentialManager` gains two members** — `ExportCredentialsAsync()` and
  `RestoreCredentialAsync(CredentialExport)`, plus the new public `CredentialExport` record
  (a full-fidelity credential including its *decrypted* payload). These back the new
  export/import commands and let each backend enumerate/restore natively rather than
  composing it above the interface. Any external `ICredentialManager` implementation must
  add both members; this warrants a **major version bump** and a matching update to the
  downstream provider packages' capped dependency range.

- **CodeQL now excludes generated and build output.** A `paths-ignore` for `**/obj/**`
  and `**/bin/**` was added to the analysis config so findings no longer surface against
  code no human maintains (e.g. the xUnit auto-generated entry point). The
  `cs/unmanaged-code` and `cs/call-to-unmanaged-code` notes on the native-backend P/Invoke
  (Keychain, libsecret, DPAPI) are inherent to what this package does and have been
  dismissed as *won't fix*; they are not defects.

- **Central Package Management adopted.** Versions move from the two project files to a
  root `Directory.Packages.props`, with `CentralPackageVersionOverrideEnabled=false` so a
  stray inline `Version=` is a hard build error rather than being silently ignored. The
  per-TFM floors are preserved exactly — CPM re-evaluates the conditional `ItemGroup`s per
  target framework during the inner build, so `net8.0` still floors at 8.0.x and `net10.0`
  at 10.0.x. **Verified behaviour-preserving: the generated `.nuspec` is byte-identical
  before and after.** Raising a floor is a consumer-visible change and deliberately not
  bundled here.
- **Properties every project restated now live in `Directory.Build.props`.** `ImplicitUsings`,
  `AnalysisLevel`, `GenerateDocumentationFile`, `EnablePackageValidation`, `IncludeSymbols`,
  `SymbolPackageFormat`, `DebugType`, `PublishRepositoryUrl`, `EmbedUntrackedSources`,
  `ContinuousIntegrationBuild`, `SatelliteResourceLanguages`, `PackageLicenseExpression` and
  `Copyright`. Duplicated settings are how the repos drifted apart in the first place; each
  csproj now carries only what is genuinely specific to it.
- **Code coverage is now collected.** Adds `Microsoft.Testing.Extensions.CodeCoverage` and,
  crucially, has CI invoke it (`dotnet test -- --coverage`) and upload the result. A
  collector that is referenced but never invoked reads as coverage while producing no data.
- **Repository baseline files adopted from NextIteration.Standards.** Adds `SECURITY.md`
  (disclosure policy, and an explicit statement of what `LocalFileCredentialEncryption`
  does *not* protect against), `CONTRIBUTING.md`, a pull request template, and a
  `CLAUDE.md` carrying the constraints an agent would otherwise violate. `global.json` now
  pins the SDK feature band with `rollForward` as well as selecting the test runner, so a
  contributor on an older SDK gets the same analyzer results as CI rather than a build that
  fails only for them. `.gitignore` and `.editorconfig` move to the canonical copies — the
  `.editorconfig` change fixes a naming rule that matched `const` fields and demanded
  `_nonceSize` for `private const int NonceSize`. No shipping code or packaging change.
- **CI adopts the shared NextIteration.Standards shape.** The single required status check
  is now `ci`, an aggregating gate over `build` and `test` that does no work itself. The
  previous `build` + `test-macos` jobs became a `build` job (restore/build/pack) and a
  `test` matrix over `ubuntu-latest` and `macos-latest`; the `gnome-keyring-daemon` setup
  is now a step guarded on `runner.os == 'Linux'`. Gating on a gate rather than on job
  names means the matrix can change without touching branch protection — a required check
  that names a matrix leg breaks the moment the matrix is edited. Also adds
  `concurrency` with `cancel-in-progress` (tag builds excepted, so a release cannot be
  half-cancelled), `timeout-minutes` on every job, and NuGet restore caching.
- **Added CodeQL code scanning** (`security-and-quality` queries) with an explicit build
  rather than autobuild, so both target frameworks are analysed.
- **Added Dependabot** with minor and patch updates grouped into a single PR and
  auto-merged behind CI; major updates arrive individually and stay open for review. The
  three packages carrying deliberate per-TFM floors have major updates suppressed outright,
  because an 8.x to 10.x bump there is never mergeable by design.
- **Migrated the test suite from xUnit.net v2 to v3.** `xunit` `2.9.3` was
  flagged deprecated ("Legacy") on NuGet and `2.9.3` is the terminal v2 release,
  so no further fixes were coming. Replaced it with `xunit.v3` `4.0.0`. Note the
  package id keeps the `.v3` suffix while its *version* is now `4.0.0` — there is
  no `xunit.v4` package. Test-project-only; no public API or packaging change.
  - The test project is now `<OutputType>Exe</OutputType>`, which v3 requires
    (its targets hard-error otherwise); the runner generates the entry point.
  - xUnit.net v3 builds on Microsoft.Testing.Platform (MTP), and the .NET 10 SDK
    refuses to run MTP test projects through the legacy VSTest target. A root
    `global.json` opts `dotnet test` into the MTP runner. The CI `dotnet test`
    invocation is unchanged.
  - Dropped `Microsoft.NET.Test.Sdk`, `xunit.runner.visualstudio`, and
    `coverlet.collector`: all three are VSTest-only and MTP replaces the runner
    entirely. Coverage was never actually collected (no `--collect` anywhere in
    CI or scripts), so nothing regressed; if coverage is wanted later, the MTP
    equivalent is `Microsoft.Testing.Extensions.CodeCoverage`.
  - Fixed 30 new `xunit.analyzers` 2.0.0 findings surfaced by v3, which
    `TreatWarningsAsErrors` promotes to errors: 15 × `xUnit2033` (use
    `Assert.Single`'s return value instead of re-indexing `[0]`) and 15 ×
    `xUnit1051` (thread `TestContext.Current.CancellationToken` into calls that
    accept one, so cancellation is responsive).

- **Dependency updates (no consumer impact).** Bumped `Microsoft.SourceLink.GitHub`
  to `10.0.400`; test-only `Microsoft.NET.Test.Sdk` to `18.9.0` and
  `xunit.runner.visualstudio` to `4.0.0`. SourceLink is referenced with
  `PrivateAssets="All"` and the other two are test-only, so none of these reach
  consumers and no dependency floor changed. The `net8.0` floors are already at
  the top of their `8.0.x` servicing lines, and the `net10.0` floors are left at
  `10.0.10` deliberately rather than raising a floor consumers would be forced to
  match. `Spectre.Console` (`0.57.2`) and `Spectre.Console.Cli` (`0.55.0`) remain
  the latest stable releases of each. No public API change.

### Fixed

- **`AtomicFile` could throw on Windows when two writers replaced the same file.** The
  atomic-replace step used `File.Move(temp, path, overwrite: true)` for every platform. On
  POSIX that is `rename(2)`, which replaces an open destination and serialises concurrent
  renames. On Windows it is `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`, which raises a
  sharing violation instead — so concurrent writers surfaced as
  `UnauthorizedAccessException: Access to the path is denied`, and the type's own
  documentation wrongly claimed the call was atomic on NTFS. Windows now uses
  `File.Replace` (`ReplaceFile`), which tolerates an open destination, with a short backoff
  for the race between testing for the destination and replacing it. Found the moment the
  test matrix started running on Windows, by a concurrency test that had been in the suite
  all along and had never executed.
- **The test matrix now runs on Windows as well as Linux and macOS.** Windows-only code
  had never been executed by any test run: `DpapiCredentialEncryption` in full, the ACL
  hardening block in `CredentialsDirectory` that strips inheritance so only the current
  user and SYSTEM can read the credentials directory, and the Windows branches of the
  unix-mode handling in `AtomicFile`, `SelectionsLock` and `FileCredentialManager`. Four
  tests written specifically for Windows behaviour were passing vacuously behind
  `if (OperatingSystem.IsWindows())`. Same class of gap as the untested `net8.0` target,
  on a security boundary the README advertises. Also bumps `actions/cache` to v6.
- **The `net8.0` target is now actually tested.** The package has multi-targeted
  `net8.0;net10.0` since 0.7.0, but the test project targeted `net10.0` only and CI
  installed just the 10.0.x SDK — so the framework whose consumers the per-TFM dependency
  floors exist to protect was shipped unverified. The test project now targets both, and
  CI installs both SDKs. The suite goes from 145 to 290 tests (145 per framework) and
  passes on both; no behavioural difference was found, so this closes a verification gap
  rather than a bug.

- **README now states the supported target frameworks accurately.** It claimed `net10.0`
  only — in the .NET badge, the install section, and Requirements — even though the package
  has multi-targeted `net8.0;net10.0` since 0.7.0. The documented dependency floors were
  stale too: `Spectre.Console` 0.54+ / `Spectre.Console.Cli` 0.53+ against actual floors of
  0.57.2 / 0.55.0, and a single `10.0+` floor for
  `Microsoft.Extensions.DependencyInjection.Abstractions` where 0.7.1 deliberately made
  those floors per-target-framework. Requirements now records the per-TFM floors and why
  they exist, so the reason net8 consumers are supported is written down rather than
  implied by the csproj. Documentation only — no code or packaging change.

## [0.7.1] — 2026-07-24

### Changed

- **Per-target-framework dependency floors.** A `PackageReference` version in a
  library is a *minimum floor* NuGet forces on every consumer, so flooring the
  runtime-aligned Microsoft platform packages at a single `10.0.x` dragged
  `net8.0` (LTS) consumers off their own `8.0.x` servicing line. Each target now
  floors at its aligned major: the `net8.0` build floors
  `Microsoft.Extensions.DependencyInjection.Abstractions` at `8.0.2`,
  `Microsoft.Extensions.Http` at `8.0.1`, and
  `System.Security.Cryptography.ProtectedData` at `8.0.0`; the `net10.0` build
  floors all three at `10.0.10`. No public API change.
- **Dependency updates.** Bumped `Spectre.Console` to `0.57.2` and
  `Microsoft.SourceLink.GitHub` to `10.0.301`; test-only `Microsoft.NET.Test.Sdk`
  to `18.8.1`. `Spectre.Console.Cli` stays at `0.55.0` (latest stable).

---

## [0.7.0] — 2026-06-20

### Added

- **Multi-targeting `net8.0` and `net10.0`.** The package now ships assemblies for
  both `net8.0` (current LTS) and `net10.0`, so consumers no longer need the newest
  runtime to take a dependency. All dependencies already provide `net8.0` assets, so
  the dependency graph is unchanged. The only source adjustment was swapping the
  `net9.0+` `System.Threading.Lock` used to guard libsecret symbol resolution for a
  plain `object` lock; behaviour is identical. No public API change.

---

## [0.6.3] — 2026-06-10

### Changed

- **Dependency updates.** Bumped `Microsoft.Extensions.DependencyInjection.Abstractions`,
  `Microsoft.Extensions.Http`, and `System.Security.Cryptography.ProtectedData`
  to `10.0.9`; `Spectre.Console` to `0.56.0`; and `Microsoft.SourceLink.GitHub`
  to `10.0.300`. Test-only dependencies updated as well
  (`Microsoft.NET.Test.Sdk` `18.6.0`, `xunit` `2.9.3`,
  `xunit.runner.visualstudio` `3.1.5`, `coverlet.collector` `10.0.1`).
  `Spectre.Console.Cli` stays at `0.55.0` (latest stable). No public API change.
- **NuGet trusted publishing.** The `publish` CI job now uses OIDC-based
  [trusted publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing):
  it exchanges the GitHub OIDC token for a short-lived nuget.org API key via
  `NuGet/login@v1` instead of a long-lived `NUGET_API_KEY` secret.

---

## [0.6.2] — 2026-05-03

### Changed

- **Symbol packaging.** Switched `<DebugType>` from `embedded` to `portable`
  so the published `.snupkg` actually contains `.pdb` files. The previous
  combination produced an empty `.snupkg`; nuget.org rejects empty symbol
  packages with HTTP 400. Until now the workflow's `upload-artifact`
  filter (`*.nupkg`) silently dropped the broken symbol package on its
  way to the publish job, so the failure stayed invisible — but no
  symbols ever reached nuget.org's symbol server. Consumers debugging
  into the library now get sources via the symbol server out of the box.
- **CI artifact path.** `upload-artifact` now captures `*nupkg` (both
  `.nupkg` and `.snupkg`) so the publish job pushes both files.

---

## [0.6.1] — 2026-05-03

### Fixed
- **Markup injection in `accounts` command output** — provider names, account names, environments, summary `DisplayFields`, exception messages, and the `--provider` flag echoed in the "Unknown provider" error now flow through `Markup.Escape` before reaching `MarkupLine` / `Table.AddRow` / Spectre selection prompts. A credential whose name happened to contain `[` or `]` previously corrupted the `accounts list` table rendering, and exception messages with markup-looking content (common on `JsonException` / IO errors) garbled the error line in `CommandErrorReporter`.
- **`accounts delete <short-id>` crash** — `accounts delete abc` (or any non-GUID id shorter than 8 chars) previously threw `ArgumentOutOfRangeException` on the `accountId[..8]` slice in the confirm prompt before reaching "not found". A new `CommandFormatting.ShortId` helper safely abbreviates, and `DeleteCredentialAsync` / `SelectCredentialAsync` / `GetCredentialByIdAsync` now validate that `accountId` is a GUID before any filesystem call. Non-GUIDs resolve to deterministic `false` on the mutating APIs and `ArgumentException` on the strict `GetCredentialByIdAsync`. Closes a path-traversal/glob-injection vector where `*` or `..\..\foo` could have flowed into `Path.Combine` and `Directory.GetFiles` patterns.
- **Concurrent `accounts select` lost updates** — `selections.json` was read-modify-written without serialization, so two CLI invocations modifying different providers could lose one provider's update. Reads/writes now happen under a cross-process advisory lock backed by `selections.json.lock` (`FileShare.None` + `FileOptions.DeleteOnClose` + exponential backoff up to ~5s). Atomic rename was already preventing torn files; this closes the lost-update window. The Keychain and libsecret backends are unaffected — both OS stores serialise their own writes.
- **Unbalanced parenthesis in `accounts select` and `accounts delete` choice prompts** — drive-by fix while replacing the unsafe `[..8]` slices.

### Changed
- **`PackageOutputPath`** — was hard-coded as `C:\nuget-local\`, which on Linux produced surprising `src/NextIteration.SpectreConsole.Auth/C:/nuget-local/…` repo churn. Now repo-relative (`$(MSBuildThisFileDirectory)..\..\artifacts\packages`) and already gitignored.
- **`GeneratePackageOnBuild`** — now scoped to `Release` builds via MSBuild condition. `dotnet test` and Debug builds no longer pack, materially shortening the local test loop.

### Tests
- 18 new tests; suite now at 145.
  - `CommandFormatting.ShortId` across full GUIDs, short strings, exact-8 boundary, null/empty.
  - Non-GUID `accountId` resolves to deterministic not-found on file-backend `Delete`/`Select`; throws on `GetCredentialByIdAsync`.
  - Concurrent `SelectCredentialAsync` on different providers both persist (regression test for the `selections.json` race).
  - `SelectionsLock` uncontended/contended/post-release semantics.

---

## [0.6.0] — 2026-04-18

### Added
- **`ICredentialManager.GetCredentialByIdAsync(providerName, accountId)`** — returns the decrypted JSON payload of a specific credential without mutating which credential is currently selected. The non-mutating counterpart to `GetSelectedCredentialAsync`. Implemented natively in all three built-in backends (`FileCredentialManager`, `KeychainCredentialManager`, `LibsecretCredentialManager`) via a single direct lookup — no select-then-read dance, no shared-state side effects.

### Breaking changes
- **`ICredentialManager` gains a required member** — `GetCredentialByIdAsync`. Consumers who have rolled their own `ICredentialManager` implementation need to add this method. (There are no default interface implementations; a no-op fallback was explicitly rejected to keep the contract honest.)

### Motivation
Consumers needed a way to read a specific stored credential's secret at runtime based on some lookup key — e.g. Mpt's `AuthenticationHelper` resolves an Adobe credential by externalId, and its `AccountsBridge.GetAll` enumerates SoftwareOne credentials when commands need ops+vendor pairs or source+dest pairs. Before 0.6.0 this required a "select credential X → read its decrypted JSON → restore the originally-selected credential" dance, which (a) leaked mutation into global state, (b) wasn't concurrency-safe, and (c) left an orphaned selection when there was no original active credential to restore. The new method makes all of that go away.

### Tests
- 14 new tests (6 File-backend, 4 Keychain, 4 Libsecret), all exercising: happy-path round-trip, unknown-id returns null, cross-provider isolation, and the core regression — **does not mutate the selected-credential state**. Suite now at 127 tests.

---

## [0.5.0] — 2026-04-18

### Changed
- Upgraded to **Spectre.Console 0.55.2** and **Spectre.Console.Cli 0.55.0** (from 0.54.0 / 0.53.1).
  - Spectre.Console.Cli 0.55 tightened `AsyncCommand<T>.ExecuteAsync` from `public` to `protected`. The four built-in command overrides (`AddCredentialCommand`, `ListCredentialsCommand`, `SelectCredentialCommand`, `DeleteCredentialCommand`) now match.
  - Spectre.Console 0.55 split `Spectre.Console.Ansi` into its own assembly. Consumers still pinned to Spectre.Console 0.54.x will hit `TypeLoadException` on `Spectre.Console.Style` at runtime; upgrade to 0.55.x when taking this release.

### Migration notes
- No source changes required on consumer code for this release — API surface is unchanged. The break is purely in the Spectre.Console dependency boundary.

---

## [0.4.2] — 2026-04-17

### Changed
- Refreshed package icon to establish a unified visual family with the three provider packages (shield-in-circle mark, shared across all four NuGet packages).

---

## [0.4.1] — 2026-04-17

### Added
- **macOS Keychain backend** (experimental). New `KeychainCredentialManager`; opt in via `CredentialStoreOptions.UseKeychain = true` + `KeychainAppIdentifier`. Each credential becomes a generic-password keychain item scoped by the consumer's app identifier.
- **Linux libsecret backend** (experimental). New `LibsecretCredentialManager`; opt in via `CredentialStoreOptions.UseKeyring = true` + `KeyringAppIdentifier`. Items are stored in the user's default Secret Service collection.
- **`CredentialStoreOptions.AdditionalEntropy`** — caller-supplied bytes mixed into PBKDF2 alongside machine identity. When set, the KEK depends on both the machine AND the entropy, so a stolen keystore file alone is not enough to decrypt. Opt-in; default behaviour is bit-identical to earlier versions.
- **`CredentialStoreOptions.KeyringCollection`** (Linux libsecret). Defaults to `"default"` (user's login keyring). Set to `"session"` for the in-memory collection that always exists on a running Secret Service daemon — useful for CI, headless environments, or ephemeral use.
- CI matrix expanded: `ubuntu-latest` (libsecret via gnome-keyring-daemon) + `macos-latest` (Keychain via Security.framework) in parallel.

### Fixed
- macOS `SecItemCopyMatching` results: `DecodeArray` now dispatches on CF type ID rather than probing with `CFDictionaryGetValue`. Probing a CFArray with a dictionary function toll-free-bridges to `[NSArray objectForKey:]` and crashes the test host on first run with `NSInvalidArgumentException`.
- macOS `errSecParam (-50)` when requesting `kSecReturnAttributes + kSecReturnData + kSecMatchLimitAll` in a single query. `QueryItems` and `QueryAllItemsForApp` now fetch attributes only and follow up per-item with `kSecMatchLimitOne` to load data — a supported combination.
- Linux libsecret tests failing against CI's fresh `gnome-keyring-daemon` (the `login` collection doesn't exist until provisioned). The library's availability probe now performs a real store + clear round-trip in `"session"` rather than a bare search.

### Changed
- `DpapiCredentialEncryption` and `CredentialEncryptionFactory.CreateDpapi` carry `[SupportedOSPlatform("windows")]` so the analyzer enforces Windows-only usage at compile time.

---

## [0.2.0] — 2026-04-17

### Added — initial public release
- **Credential store abstraction** — `ICredentialManager`, `FileCredentialManager`.
- **AES-GCM encryption** via `LocalFileCredentialEncryption` with PBKDF2-HMAC-SHA256 at 600,000 iterations.
- **DPAPI encryption** (Windows) via `DpapiCredentialEncryption`.
- **Hardened on-disk format**: atomic file writes (temp-file + rename), Unix 0600/0700 permissions, Windows ACL hardening, path-traversal validation. No unencrypted fallback.
- **Spectre.Console CLI commands**: `accounts add | list | select | delete` branch, drop-in via `CommandConfiguratorExtensions.AddAccountsBranch()`.
- **Extensibility points**:
  - `ICredentialCollector` — provider-specific prompts for `accounts add`
  - `ICredentialSummaryProvider` — provider-specific display fields for `accounts list`
  - `IAuthenticationService<TCredential, TToken>` — provider-specific authentication logic
- **DI wiring** via `ServiceCollectionExtensions.AddCredentialStore(…)`.
- Full XML documentation on the public surface.
- Test suite (xUnit) with 113 tests covering encryption, persistence, CLI command flows.
- SourceLink, deterministic builds, embedded symbols, published symbol packages.
- `TreatWarningsAsErrors=true`, `AnalysisLevel=latest` — zero-warning public API.

[0.7.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.7.0
[0.6.3]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.6.3
[0.6.2]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.6.2
[0.6.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.6.1
[0.5.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.5.0
[0.4.2]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.4.2
[0.4.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.4.1
[0.2.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.2.0

# Changelog

All notable changes to `NextIteration.SpectreConsole.Auth` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.6.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.6.1
[0.5.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.5.0
[0.4.2]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.4.2
[0.4.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.4.1
[0.2.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.2.0

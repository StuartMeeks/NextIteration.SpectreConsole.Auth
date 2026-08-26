# Changelog

All notable changes to `NextIteration.SpectreConsole.Auth` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Breaking

- **`ICredentialManager` members now take a `CancellationToken`** (#74). Every member gains a
  trailing `CancellationToken cancellationToken = default`. Existing *callers* keep compiling —
  the parameter is optional — but any external **implementation** of the interface must update
  its signatures. The three built-in backends are updated. `ICredentialCollector` and
  `ICredentialSummaryProvider` are untouched, so the provider packages are unaffected.

  The libsecret backend now binds the token to a `GCancellable` for every call, so
  cancellation reaches libsecret rather than stopping at the managed boundary. The Keychain
  backend honours the token at entry; Security.framework's `SecItem*` API offers no
  mid-call cancellation, and that is documented rather than faked.

  **What this does not fix, verified rather than assumed:** it does not rescue the KWallet
  wedge that prompted the issue. Against `ksecretd` the cancellation callback does fire, but
  the call still never returns, because ksecretd emits the prompt's `Completed` signal with an
  `ao` payload where libsecret expects `o` — libsecret's `secret_service_real_prompt_async`
  GTask is then *"finalized without ever returning"* and its nested main loop never exits.
  That is an upstream libsecret/KWallet incompatibility, and it is recorded in the backend's
  remarks instead of being papered over.

  This makes the next release **2.0.0**; the version bump itself is a separate release PR.

### Changed

- **The libsecret backend is now documented as GNOME Keyring only** (#19). It was described
  as working with "GNOME Keyring, KWallet's shim, any Secret Service implementation", which
  testing disproved. KWallet's shim (`ksecretd`) fails unattended in two distinct ways: it does
  not provide the `session` collection GNOME Keyring offers, so selecting it fails with
  *"No such object path `/org/freedesktop/secrets/aliases/session`"*; and against the default
  collection it raises a wallet-unlock prompt which, with no GUI, blocks the caller forever.
  The README and the XML docs now say what is actually validated, and `KeyringCollection`
  notes that `"session"` is a GNOME convenience rather than a portable value. Documentation
  only — no behaviour change. The blocking-call defect the validation surfaced is tracked
  separately in #74.

### Fixed

- **Three CodeQL alerts introduced by this cycle's changes**, all in code added since 1.1.0.
  `AtomicFile.WriteTempAsync` held its `FileStream` in a local before an `await using` block,
  which the analyser could not prove disposed on every path (`cs/local-not-disposed`, the only
  warning of the three) — it is now an `await using` declaration.
  `LibsecretCredentialManager.ResolveStoredProviderName` used a filter-then-project loop where
  LINQ says it plainly (`cs/linq/missed-select`), and a test paired `ContainsKey` with the
  indexer instead of `TryGetValue` (`cs/inefficient-containskey`).

- **The Keychain backend could see another CLI's credentials** (#55). App scoping was a
  dot-prefix match on the service string, and since the service is `{app}.{provider}` and
  provider names may contain dots, app `com.acme.cli` could not distinguish its own
  `pro.Adobe` item from app `com.acme.cli.pro`'s `Adobe` item. The neighbour could list,
  export **and delete** credentials it did not own; reverse-DNS identifiers nest by
  convention, so the collision is plausible rather than contrived. Items now record their
  owning app in `kSecAttrComment` and every query filters on it exactly. Items written before
  this release carry no owner and fall back to the old prefix test, so nothing already stored
  becomes invisible — meaning **legacy items stay ambiguous until rewritten**, and only items
  written from this release on are scoped exactly.

- **`RestoreCredentialAsync_Preserves…` flaked on the OS-native backends** (#61). The test
  retried until one credential was visible and then asserted `IsSelected`, which comes from a
  *separate* store item written moments earlier — so the credential could become visible
  before the selection did and the assertion ran against a half-visible store. Observed once
  on the macOS runner. The retry predicate now covers the property being asserted.

- **`SelectionsLock`'s sentinel cleanup and exhaustion path were untested** (#57). The suite
  covered acquire, contend and re-acquire, but never asserted that `FileOptions.DeleteOnClose`
  actually removes the sentinel — one test's comment claimed it without checking — so dropping
  that flag would have left a permanent lock file and still passed. The ~5.1 s backoff ladder
  ending in a thrown `IOException` was never reached either, leaving its message and its
  behaviour under a stuck peer unverified. Both are now asserted, along with the lock's actual
  job: four concurrent holders with overlapping critical sections detected directly, rather
  than inferred from one same-process test.

- **The Windows ACL hardening was verified by no test, behind a comment claiming it was**
  (#47). `CredentialsDirectoryTests` skipped its Windows case with *"verified via the file-perm
  integration path"*, and no such path existed anywhere in the suite — grepping for
  `GetAccessControl`, `FileSystemAccessRule` and `DirectorySecurity` returned nothing. So a
  regression in `CredentialsDirectory.CreateWithWindowsAcl` — wrong SID, inheritance left
  enabled, an ACE dropped — would have shipped green on all three platforms, while ACL
  hardening is one of the two reasons `CLAUDE.md` gives for keeping the Windows CI leg at all.
  There is now a test asserting inheritance is disabled and that the rule set is *exactly* the
  current user and SYSTEM, each with `FullControl` and `Allow`. Asserting the whole set rather
  than the presence of one rule is what catches an extra grant.

- **Replacing an existing selection was never tested on any backend** (#51). Every
  `SelectCredentialAsync` call in the suite was either a first selection or a negative case,
  and the only multi-select test used *different* providers — so `KeychainCredentialManager`'s
  `WriteSelection` never reached its `SecItemUpdate` branch, and the equivalent replace paths
  on libsecret and the file backend were equally unexercised. That is the path every
  `accounts select` after the first takes, and swapping between a prod and a sandbox
  credential is the headline use case in the README. All three backends now have a test that
  selects a second credential for the same provider and asserts exactly one ends up selected,
  with the right payload resolved.

- **`DeleteCredentialAsync_ClearsSelection` asserted a null that the credential's absence
  produced anyway** (#50), on all three backends. `GetSelectedCredentialAsync` resolves the id
  from the selection record and then reads the credential, which is gone — so it returned null
  whether or not the selection had been cleared, and the test passed with the entire clearing
  block deleted. The file and libsecret tests now assert on the selection **record** itself
  (`selections.json`, and the keyring's selection item via interop), which fails against a
  removed clearing block. All three also pin that an unrelated provider's selection survives
  the delete, catching over-broad clearing. The Keychain assertion remains weaker by
  necessity — reaching its selection item would need a Security.framework query from the test
  — and says so in place rather than reading as equivalent coverage.

- **libsecret leaked `SecretRetrievable` references when its search loop threw** (#56). The
  per-item `g_object_unref` was the last statement of the loop body, so a throw part-way
  through — `ThrowIfGError` on a locked collection or a per-item D-Bus error — skipped the
  current item and every remaining one, while the `finally` called only `g_list_free`, which
  releases the node structure and not the references the nodes hold. The `finally` now uses
  `g_list_free_full` with `g_object_unref` as the destroy function, the idiomatic GLib form
  for this ownership shape, so the references are released on every path.

- **`accounts export` wrote the whole archive at default permissions before tightening them**
  (#54). `AtomicFile` created its temp file with the umask default and chmod'd to `0600` only
  after the entire payload had landed. For credential files and the keystore that is shielded
  by the credentials directory's own `0700`, but `accounts export` writes to a destination the
  user chooses — exporting to `/tmp` or any shared directory left every secret in the store
  readable for the duration of the write. Temp files are now created with their final mode via
  `FileStreamOptions.UnixCreateMode`, so the window does not exist.

- **An imported archive dictated its own PBKDF2 iteration count, unbounded** (#53). The value
  came from the archive's clear-text envelope with only a `> 0` check and fed straight into
  `Rfc2898DeriveBytes.Pbkdf2`. `Iterations` is an `int`, so a hostile or corrupt archive could
  ask for up to ~2.1 billion and hang `accounts import` on CPU before any passphrase check
  could fail — and could equally advertise `1`, silently deriving with a work factor far below
  what the library documents. The count is now required to fall between the documented 600,000
  and a generous ceiling (20×), with `0` still meaning "written before the field existed" and
  falling back to the default. Out-of-band values are **rejected rather than clamped**:
  deriving with a different work factor than the file asks for would just fail the
  authentication tag and surface as a misleading "wrong passphrase".

- **The libsecret backend reported a successful delete when nothing was deleted** (#45).
  `ClearItem` discarded the gboolean from `secret_password_clearv_sync` and
  `DeleteCredentialAsync` returned `true` unconditionally, so `accounts delete` printed
  "Credential deleted successfully." and exited 0 for a credential still in the keyring —
  the worst possible answer for someone revoking a leaked secret. `clearv` removes only
  *unlocked* matches and reports "nothing removed" by returning FALSE **without** setting a
  GError, so nothing else caught it. The result is now threaded through and a delete that
  removed nothing returns `false`, leaving the selection untouched because the credential it
  points at still exists. The Keychain backend already checked its status and is unchanged.

- **Provider-name casing behaved differently on each of the three backends** (#49).
  `ICredentialManager` documented no case-sensitivity contract, and the implementations
  disagreed: the file backend matched `OrdinalIgnoreCase`, while the Keychain and libsecret
  backends keyed every lookup on the caller's exact spelling. A consumer developed against
  the default file backend that passed a differently-cased provider name worked there and
  silently returned nothing once `UseKeychain` or `UseKeyring` was set. The contract is now
  stated on `ICredentialManager` — **provider names are matched case-insensitively and stored
  as supplied** — and both OS backends honour it by resolving the caller's spelling to the
  stored one. Resolution rather than normalisation, deliberately: the provider name is part
  of those backends' storage keys, so lowercasing the key would orphan every item already
  stored under a mixed-case spelling. One difference is documented rather than fixed — a store
  holding two spellings of one provider lists both on the file backend and one on the native
  backends, which the normal path cannot produce.

- **`accounts list` could show a credential as selected that the consumer could not resolve**
  (#48). `selections.json` deserialised into a default ordinal dictionary, so
  `GetSelectedCredentialAsync` missed a selection recorded under a differently-cased provider
  spelling — while `ListCredentialsAsync`, which matches `OrdinalIgnoreCase`, still reported
  that same credential as selected. The result was a green tick in the listing next to
  "No credential selected" from the consumer's `AuthenticateAsync()`. The selection map is now
  keyed `OrdinalIgnoreCase`, matching every other provider comparison in the class, and a
  hand-edited file holding two spellings of one provider is tolerated rather than throwing.

- **A summary provider that threw made the whole credential vanish from `accounts list`**
  (#52). The per-file `catch (JsonException)` in `FileCredentialManager.ListCredentialsAsync`
  spanned the entire loop body, including the consumer's `GetDisplayFields` call. Since the
  README's own worked example projects with `System.Text.Json`, a payload shape it could not
  parse threw `JsonException` and the credential was silently dropped from the listing — not
  marked, not counted, just absent, which also hid the id needed to run `accounts delete` on
  it. The JSON catch is now scoped to the deserialize step, and the projection is guarded
  separately: a throwing provider costs that row its provider columns and marks it
  `IsDecryptable = false`, never its existence. `IsDecryptable`'s documentation is widened to
  match — it now means "this row's provider columns could not be produced", covering both an
  unavailable payload and a projection that threw.

- **The libsecret test suite disabled itself when the code it tests regressed** (#46). Its
  availability probe performed a real store + clear through `AddCredentialAsync` /
  `DeleteCredentialAsync` inside a catch-all, so a regression in exactly the code under test
  made the probe throw, set the skip flag, and turn all ~20 tests into no-ops that still
  reported as passing. The probe now uses the interop layer directly — a read-only search
  against attributes nothing can match — and touches no part of the manager. Sabotaging
  `AddCredentialAsync` now produces 46 failures where it previously produced none.
  Platform-guarded tests in both the libsecret and Keychain suites also report as **skipped**
  instead of returning early and counting as passed, so a run that verifies nothing says so:
  50 skipped on Linux where the total previously read `skipped: 0`.

- **Two concurrent first runs could silently destroy one set of credentials** (#44). Keystore
  creation was an unlocked check-then-write: both invocations found no `.keystore`, both spent
  ~200ms deriving a KEK, and the second write replaced the first via an unconditional atomic
  overwrite. Anything the first process had already encrypted was then permanently
  undecryptable — and it surfaced as the same "failed integrity check" message as a keystore
  copied between machines, so it was easy to misdiagnose. `AtomicFile` gains
  `TryWriteNewAsync`, a temp-then-**non-overwriting**-rename, so the losing racer discards its
  key and adopts the winner's instead of persisting data under a key no longer on disk.
  Crash-safety is unchanged; only the final rename's overwrite behaviour differs.

- **The Keychain and libsecret backends exported an empty credential when a secret failed to
  load** (#42). Both fabricated a blank payload rather than skipping the item —
  `item.Secret ?? string.Empty` on libsecret, the `item.Data is not null ? … : string.Empty`
  ternary on Keychain. Since `ExportCredentialsAsync` is the read half of `accounts export` and
  `CredentialData` flows straight into the archive, a secret that failed to load was written to
  the bundle as a valid-looking credential holding nothing, and the next import restored that
  over a real secret — surfacing only later, as an empty credential at authentication time.

  This is the same silent-corruption shape 1.1.0 fixed in the file backend, reached by a
  different route: there the payload failed to *decrypt*, here it fails to *load* from the OS
  store (a locked collection, an item removed between enumeration and read, or a per-item
  D-Bus/Security.framework failure). Such an item is now skipped, matching the file backend, and
  `accounts export` already warns with the skipped count.

  On libsecret the skip needed a fix one layer down to work at all.
  `LibsecretInterop.ReadSecretValueAsString` returned `string.Empty` for a NULL `SecretValue`,
  collapsing "the secret did not load" into "the secret is an empty string" before the manager
  ever saw it — so a guard on `item.Secret is null` could never fire. It now returns `string?`
  and yields `null` in that case, which is the state
  `secret_retrievable_retrieve_secret_sync` reports (without setting a GError) when an item
  vanishes between the search and the retrieve. An empty-but-present secret, a valid data pointer
  of length zero, is still a legitimate stored value and still reads as `string.Empty`.

  `ListCredentialsAsync` on both backends now also reports `IsDecryptable = false` when a
  summary provider is registered but the secret did not load, so the flag added in 1.1.0 means
  the same thing on all three backends rather than only on the file one. On libsecret this
  depended on the same interop fix; it additionally stops `GetDisplayFields` being handed an
  empty string, which a JSON-parsing summary provider would have thrown on, taking down the whole
  listing.

  Scope of the skip, stated precisely: it covers an item that disappears between enumeration and
  read. A locked collection or a per-item transport error still aborts the whole export —
  libsecret sets a GError and Keychain returns a non-`errSecItemNotFound` status, and both are
  raised rather than skipped. The targeted fetch paths were already correct and are unchanged.

  `ICredentialManager.ExportCredentialsAsync` is documented accordingly: implementations **must**
  omit a credential they cannot read rather than return it with an empty payload, and the returned
  count can therefore be lower than the number stored.

## [1.1.0] — 2026-08-24

One behaviour fix, one additive public member, three documentation fixes. Credentials the local
keystore cannot open no longer break `accounts list`, `accounts export` or `accounts import` —
previously a single unreadable credential file took down all three, including the import that was
meant to repair it. Minor rather than patch because `CredentialSummary` gains a member; the
addition is source- and binary-compatible, no dependency floor moved, and nothing on disk changed
format. Drop-in over 1.0.1.

### Added

- **`CredentialSummary.IsDecryptable`** — distinguishes "the stored payload could not be
  decrypted" from "no `ICredentialSummaryProvider` is registered for this provider", both of which
  otherwise present as an empty `DisplayFields`. `accounts list` uses it to mark a broken row
  `(unreadable)` instead of rendering it as ordinary. Additive: not `required` and defaults to
  `true`, so existing external `ICredentialManager` implementations keep compiling untouched. It is
  documented as a display hint rather than a guarantee — nothing is decrypted when no summary
  provider is registered, so it stays `true` for an unreadable credential in that case; callers
  needing certainty should use `GetCredentialByIdAsync`, which throws.

### Fixed

- **`accounts import` aborted when any existing local credential could not be decrypted**
  (#38). The reported failure surfaced as *"Credential data failed integrity check … the
  keystore was copied from another machine or user"* on a correct passphrase, because the
  message came from the local keystore, not the archive. `ImportAsync` called
  `ExportCredentialsAsync` to build its conflict index, and the file backend's `DecryptAsync`
  there sat outside the `try`/`catch` — so one unreadable credential file in the destination
  vetoed the whole import. That fired in exactly the situation export/import exists to fix: a
  credentials directory carried to a new machine, then repaired via export/import.

  The root cause was deeper than a missing `catch`. Conflict detection only ever needed the
  provider, account name and environment — all stored in plaintext — never the encrypted
  payload, and the resolver `accounts import` builds ignores the existing side entirely. The
  index is now built from metadata via `GetProviderNamesAsync` + `ListCredentialsAsync`, so an
  import no longer decrypts the store at all and no longer materialises every secret in memory
  for an operation that never reads one. All the affected types are `internal`; no public API
  change and no `ICredentialManager` member added.

- **`accounts list` died entirely when one credential could not be decrypted** (#38). The same
  unguarded decrypt in `ListCredentialsAsync` (inside a `try` catching only `JsonException`)
  took out the whole listing for a provider whenever an `ICredentialSummaryProvider` was
  registered for it — which also blocked the repair path, since `accounts delete <id>` needs
  the id to be visible. A broken row now renders without its provider columns and is marked
  `(unreadable)`, with a hint pointing at `--on-conflict overwrite` and `accounts delete`.

  `CredentialSummary` gains `IsDecryptable` to distinguish "payload unreadable" from "no
  summary provider registered". Additive: not `required`, defaults to `true`, so external
  `ICredentialManager` implementations are unaffected.

- **`accounts export` now reports credentials it had to leave out.** An unreadable credential
  is skipped rather than aborting the export, but it is *dropped* rather than written with an
  empty payload — `CredentialData` flows straight into the archive, so a blank secret would
  become silent corruption at the next import. A short archive is otherwise invisible until a
  restore comes up empty, so the count is now warned about, and an export where *everything*
  failed to decrypt reports that and exits non-zero instead of claiming "nothing to export".

  `GetSelectedCredentialAsync` and `GetCredentialByIdAsync` deliberately still throw. Those
  are targeted fetches: returning `null` would masquerade as "no credential selected" and hand
  a consumer a worse diagnosis than the real one. Tests pin that split so a future over-broad
  catch cannot erode it.

  File backend only — the Keychain and libsecret backends read secrets straight from the OS
  store and never call `ICredentialEncryption`.

- **The README's Contributing section pointed at the retired `TODO.md`.** That file was
  removed in #25 when its backlog moved to GitHub issues, but the change never updated the
  README, so the link has been dead since 1.0.0. The same sentence also listed keystore
  format versioning and zero-on-dispose for caller-supplied entropy as outstanding hardening
  when both shipped in 1.0.0 — advertising finished work as a backlog. It now points at the
  issue tracker and names only the two genuinely open items: ACL-scoped Keychain access (#18)
  and libsecret KWallet validation (#19).

- **`CredentialEncryptionFactory.Create` carried the same retired-TODO reference in its XML
  doc**, which ships in the generated docs and `.snupkg`. It was stale three ways: the TODO
  is gone, both OS-native backends have since shipped, and the premise was wrong — the
  Keychain and libsecret backends replace `ICredentialManager` and never pass through
  `ICredentialEncryption`, so this factory could never have returned them. The doc now says
  what actually selects those backends. XML docs only; no API surface change.

- **Dropped ACL-scoped Keychain access from the README's outstanding-hardening list.** Issue
  #18 was closed as won't-do: binding credential items to the creating binary was
  investigated and rejected, so listing it as planned work was misleading.

## [1.0.1] — 2026-08-22

Maintenance release. No API or behavior change for consumers: a behavior-identical
hardening of an internal null-check in the file backend, plus a CI-only move to buildless
CodeQL analysis. Safe drop-in over 1.0.0.

### Changed

- **CodeQL now analyses the C# source buildless** (NextIteration.Standards §4.4). The
  `codeql.yml` init step moves to `build-mode: none` and the explicit `Setup .NET`,
  `Restore`, and `Build` steps are dropped. This is load-bearing, not a simplification:
  GitHub applies the `paths-ignore` filter *only* under buildless extraction — under a
  compiled build every file the compiler sees is analysed, `obj/` included, so the
  `**/obj/**` exclusion this repo already declared was silently inert and the xUnit
  auto-generated entry point in `obj/` was being analysed. Buildless extraction also reads
  every target framework at once, where autobuild could pick a single TFM and analyse half
  the code. Adopts the revised canonical `codeql.yml` verbatim; no query coverage changes.

- **Rewrote the provider-match guard in `FileCredentialManager.ListCredentialsAsync`**
  from `credential?.ProviderName.Equals(…) == true` to an explicit
  `credential is not null && …`. Behavior is identical, but the null state now flows into
  the block body — which dereferences `credential` throughout — so both the compiler and
  CodeQL can prove the accesses safe. Resolves the `cs/dereferenced-value-may-be-null`
  alert the corrected buildless analysis surfaced (a genuine code fix, not a dismissal).

## [1.0.0] — 2026-08-21

First stable release. Headline: whole-store **export/import** to move credentials
between machines. **Breaking:** `ICredentialManager` gains `ExportCredentialsAsync` and
`RestoreCredentialAsync` plus the `CredentialExport` record — any external implementation
must add both members.

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

- **CodeQL now excludes the two P/Invoke audit queries at the config level** (NextIteration.Standards
  §4.4). A `query-filters` block in `codeql.yml` excludes exactly `cs/unmanaged-code` and
  `cs/call-to-unmanaged-code` — audit queries that fire on every P/Invoke into Keychain,
  libsecret, and DPAPI and that no code change can resolve (native interop is the point).
  Every other `security-and-quality` query still runs on the interop files, so no real
  finding is lost. This replaces the per-alert *won't fix* dismissals, which reopened
  whenever a reformat shifted a line number.

- **Enabled `EnforceCodeStyleInBuild`** (NextIteration.Standards §1.2.1, now a `MUST`). The
  canonical `.editorconfig`'s gated rules now fail the build instead of merely showing in
  the IDE, so the house style is enforced. Bringing the code green under the flag was a
  mechanical, behavior-preserving reformat — braces on all single-statement `if`s, block-
  scoped namespaces (the interop layer and tests were file-scoped), and minor
  expression-body/accessibility/collection-expression fixes — applied with `dotnet format`.
  `IDE0005` is suppressed in the **test** project only: it requires `GenerateDocumentationFile`,
  which §2.7 sets to `false` for tests, so gating it there would hard-error; it still gates
  the shipping project. (§2.7 needs the matching amendment estate-wide.)

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

[Unreleased]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v1.1.0
[1.0.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v1.0.1
[1.0.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v1.0.0
[0.7.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.7.1
[0.7.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.7.0
[0.6.3]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.6.3
[0.6.2]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.6.2
[0.6.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.6.1
[0.5.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.5.0
[0.4.2]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.4.2
[0.4.1]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.4.1
[0.2.0]: https://github.com/StuartMeeks/NextIteration.SpectreConsole.Auth/releases/tag/v0.2.0

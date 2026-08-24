# CLAUDE.md — NextIteration.SpectreConsole.Auth

## This package

Encrypted credential storage plus a ready-made `accounts` command branch for CLI tools
built on Spectre.Console. Consumers register a credential store and one or more auth
providers, then get `accounts add/list/select/delete` wired into their existing
`CommandApp`. Storage backends are pluggable: an AES-GCM local file by default, or the
OS-native stores — macOS Keychain, Linux libsecret, Windows DPAPI.

The provider packages in `NextIteration.SpectreConsole.Auth.Providers` consume this one
through a major-capped range — the 1.0.1 providers all depend on `[1.0.1, 2.0.0)` — so a
breaking change to `ICredentialCollector` or `ICredentialSummaryProvider` is a downstream
event, not a local one.

Note what that cap does and does not do. It sits at the **major** boundary, so it will not
protect those packages from a break shipped in a 1.x release: any 1.x satisfies the range
and gets resolved. The only thing keeping the providers working is not breaking those two
interfaces within 1.x. (This note previously recorded the providers' pre-1.0 cap of
`[0.7.1,1.0.0)`, which excluded every 1.x release of this package; the providers widened it
when they went 1.0.x, and this note was not updated with them.)

## Things that are easy to get wrong here

- **Per-TFM dependency floors are deliberate.** `Microsoft.Extensions.*` and
  `System.Security.Cryptography.ProtectedData` are floored at 8.0.x for `net8.0` and
  10.0.x for `net10.0`. Raising the net8 floor to a 10.x version drags every net8 LTS
  consumer off its own servicing line. Dependabot is configured to never propose it; do
  not do it by hand either.
- **The test matrix runs Linux, Windows and macOS because each has a real backend** —
  libsecret, DPAPI plus ACL hardening, and Keychain respectively. Platform-guarded tests
  pass vacuously off their platform, so dropping a leg silently stops testing a shipped
  code path. This is not theoretical: adding the Windows leg immediately found a
  concurrency bug in `AtomicFile`.
- **Atomic replace is not the same call on every platform.** POSIX uses `File.Move` with
  overwrite (`rename(2)`); Windows must use `File.Replace` (`ReplaceFile`), because
  `MoveFileEx` raises a sharing violation when the destination is open or two replacements
  race. See the remarks on `AtomicFile`.
- **`LocalFileCredentialEncryption`'s security boundary is filesystem permissions**, not
  the KEK — it is derived from non-secret machine identifiers unless the caller supplies
  `AdditionalEntropy`. Do not describe it as protecting against same-user code.

## Repository baseline

This repo conforms to
[NextIteration.Standards](https://github.com/StuartMeeks/NextIteration.Standards).
Build properties, test stack, CI shape, and branch protection are defined there, not
here. Before changing any of those, read `STANDARD.md`; if this repo needs to deviate,
that is an `EXCEPTIONS.md` entry in the standards repo, not a local difference.

## Non-negotiables

- **The build must be clean.** `TreatWarningsAsErrors` is on and analyzers run at
  `latest`. A warning is a build failure.
- **Tests must pass on every shipped target framework** (`net8.0` and `net10.0`). A change
  that only passes on one is not finished. Shipping a target you do not test is a defect,
  not a scoping decision.
- **Dependency floors are deliberate and per-TFM.** A `PackageReference` version in a
  library is a *minimum* NuGet forces on every consumer, so raising a floor is a
  consumer-visible change even when nothing in the code needs it. Never raise one to
  silence a warning.
- **Public API changes need XML docs.** `GenerateDocumentationFile` is on and the public
  surface is fully documented.
- **Update `CHANGELOG.md`** under `[Unreleased]`, saying what changed and why.

## Dependabot

Minor and patch updates auto-merge behind CI. Major updates stay open for a human — that
is deliberate, not a backlog to clear. Packages with per-TFM floors have major updates
suppressed entirely via `ignore`; bump those by hand when a new .NET major lands.

## After opening a pull request

Watch CI to completion, report the real check results, then **offer to merge** in the same
message. Do not stop silently and wait to be asked.

- If branch protection blocks the merge, say so and offer `gh pr merge --admin`. These
  repos require a code-owner review only the maintainer can give, which is why `--admin` is
  the tool — but that mechanic is not the reason the offer is wanted. The reason is simply
  that the maintainer has grown comfortable delegating this to an agent, so treat the
  latest instruction as authoritative over this file.
- **Merge only on an explicit yes.** The offer is pre-approved; the action is not.
- Never offer while checks are failing or still running. Report that state instead.
- Report the checks that actually ran. A skipped check is not a passing check, and branch
  protection treats them differently from how they read in a summary.

## CI

The single required status check is `ci` — an aggregating gate over `build` and `test`.
Renaming those jobs is safe; the ruleset never names them. Do not make them required
checks directly.

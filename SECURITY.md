# Security policy

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button under this
repository's Security tab, which opens a private advisory visible only to the
maintainers. Please do not open a public issue for a suspected vulnerability.

Include the affected package and version, what an attacker can achieve, and a
reproduction if you have one.

You can expect an acknowledgement within 7 days, an assessment within 14, and
credit in the advisory and changelog unless you ask otherwise.

## Supported versions

Only the latest released minor of each package receives security fixes. These are
pre-1.0 libraries and there are no long-term support branches.

## Scope

These libraries store credentials on the local filesystem or in an OS secret store.
Two things are explicitly **not** claimed:

- `LocalFileCredentialEncryption` derives its key-encryption key from non-secret
  machine and user identifiers. Its real security boundary is filesystem permissions.
  It protects credentials at rest against another *user*; it does not protect them
  against code running as the same user. Supply `AdditionalEntropy` for a KEK that
  depends on a caller-held secret as well as the machine.
- Nothing here defends against a compromised host, a debugger attached to the
  process, or a heap dump taken while credentials are decrypted in memory.

Reports demonstrating a break *within* those stated boundaries are in scope and
welcome. Reports that only restate a documented limitation are not vulnerabilities.

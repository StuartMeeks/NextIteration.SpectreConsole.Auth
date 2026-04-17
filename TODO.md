# TODO

## Credential store backends

`LocalFileCredentialEncryption` protects credentials with AES-GCM but relies on
filesystem permissions for its real security boundary — the key-encryption key
is derived from non-secret machine/user identifiers. For stronger protection
against a local attacker, the library should offer OS-native secret-store
backends on platforms that have them.

### ✅ KeychainCredentialManager (macOS) — **experimental, shipped**

An `ICredentialManager` implementation backed directly by the macOS Keychain.
Each credential is a generic-password keychain item scoped by the consumer's
`KeychainAppIdentifier`. Opt in via `CredentialStoreOptions.UseKeychain = true`.

Still outstanding:
- Harden with ACL-scoped access (require the running binary to match the
  creator, so a neighbouring app can't read another CLI's items even with
  the same app identifier).
- Batch-test against multiple macOS versions via CI matrix.
- Decide whether to expose `UseKeychain = true` as the default on macOS
  (currently opt-in while experimental).

### ✅ LibsecretCredentialManager (Linux) — **experimental, shipped**

An `ICredentialManager` implementation backed directly by libsecret /
the Secret Service API. Each credential becomes a Secret Service item in
the user's default keyring. Opt in via
`CredentialStoreOptions.UseKeyring = true`.

Still outstanding:
- Validate against KWallet's Secret Service shim (current tests only
  exercise GNOME Keyring).
- CI currently starts `gnome-keyring-daemon` inline; consider splitting
  the Linux tests into a separate job mirroring the macOS pattern for
  cleaner signal.
- Decide whether to expose `UseKeyring = true` as the default on Linux
  when a Secret Service is detected (currently opt-in while experimental).

## LocalFileCredentialEncryption hardening

### ✅ Optional caller-supplied entropy — **shipped**

`LocalFileCredentialEncryption` now accepts `byte[]? additionalEntropy` via
its constructor, surfaced on `CredentialStoreOptions.AdditionalEntropy` and
`CredentialEncryptionFactory.Create` / `CreateLocalFile`. When set, the
entropy is concatenated with the machine identity on the password side of
PBKDF2, so the KEK depends on both the machine AND the caller-supplied
secret. An attacker with just the keystore file can no longer decrypt.

Default behaviour (entropy omitted / null / empty) is bit-identical to
earlier versions — no breaking change for existing consumers. Supplying a
value is a breaking on-disk format change for that keystore specifically;
consumers rotating the entropy need to delete the keystore and re-add
credentials.

### Future hardening ideas

- Keystore format versioning (1-byte header magic) so migration across
  future KDF changes can produce a clear "unsupported format" error
  instead of an integrity-check failure.
- Zero-on-dispose for the in-memory entropy buffer, so a heap dump taken
  after the app exits doesn't expose the secret. Currently the GC reclaims
  it on object disposal, but without clearing.

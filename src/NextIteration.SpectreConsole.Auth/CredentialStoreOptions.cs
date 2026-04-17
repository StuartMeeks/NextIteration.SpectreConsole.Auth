namespace NextIteration.SpectreConsole.Auth
{
    /// <summary>
    /// Options passed to <c>AddCredentialStore</c> to configure the credential store.
    /// </summary>
    public sealed class CredentialStoreOptions
    {
        /// <summary>
        /// Absolute path to the directory where encrypted credential files and
        /// the keystore are stored. Required when using the default file-based
        /// backend (i.e. when <see cref="UseKeychain"/> is <see langword="false"/>
        /// or when running on a non-macOS platform).
        /// </summary>
        public string CredentialsDirectory { get; set; } = string.Empty;

        /// <summary>
        /// Optional caller-supplied entropy mixed into the key-derivation
        /// step of the file-based backend. When set, the key-encryption key
        /// depends on this value in addition to the machine-derived inputs —
        /// the file-based backend then requires both the keystore file AND
        /// the entropy value to decrypt (closes the "keystore is enough"
        /// weakness of the default mode).
        /// </summary>
        /// <remarks>
        /// Ignored when <see cref="UseKeychain"/> or <see cref="UseKeyring"/>
        /// is set — those backends use OS-native secret stores and don't
        /// touch the PBKDF2 path. Changing the entropy value invalidates
        /// any existing keystore; delete the keystore and re-add credentials
        /// whenever the entropy changes.
        /// </remarks>
        public byte[]? AdditionalEntropy { get; set; }

        /// <summary>
        /// Opt-in flag to use the macOS Keychain as the credential store
        /// instead of the file-based backend. Only honoured when running on
        /// macOS — setting this on any other platform throws during
        /// registration.
        /// </summary>
        /// <remarks>
        /// The Keychain backend is marked <b>experimental</b>. Validate in
        /// your own environment before depending on it.
        /// </remarks>
        public bool UseKeychain { get; set; }

        /// <summary>
        /// Reverse-DNS identifier used to scope this CLI's Keychain items
        /// (e.g. <c>com.mycompany.my-cli</c>). Required when
        /// <see cref="UseKeychain"/> is <see langword="true"/>. Items from
        /// different apps sharing the same login keychain must use distinct
        /// identifiers to avoid collision.
        /// </summary>
        public string KeychainAppIdentifier { get; set; } = string.Empty;

        /// <summary>
        /// Opt-in flag to use the Linux Secret Service (libsecret) as the
        /// credential store instead of the file-based backend. Only
        /// honoured when running on Linux AND a Secret Service daemon is
        /// reachable — setting this on any other platform throws during
        /// registration.
        /// </summary>
        /// <remarks>
        /// The libsecret backend is marked <b>experimental</b>. Requires a
        /// running Secret Service (GNOME Keyring, KWallet's shim, etc.);
        /// headless containers typically lack one and registration will
        /// surface a clear error.
        /// </remarks>
        public bool UseKeyring { get; set; }

        /// <summary>
        /// Reverse-DNS identifier used to scope this CLI's keyring items
        /// (e.g. <c>com.mycompany.my-cli</c>). Required when
        /// <see cref="UseKeyring"/> is <see langword="true"/>.
        /// </summary>
        public string KeyringAppIdentifier { get; set; } = string.Empty;

        /// <summary>
        /// Secret Service collection that stored items are written to.
        /// Defaults to <c>"default"</c> (usually the user's login keyring).
        /// Set to <c>"session"</c> for the in-memory session keyring that
        /// always exists on a running Secret Service daemon — useful for
        /// CI environments where the login keyring has not been
        /// provisioned, or for ephemeral use where persistence isn't
        /// required. Only consulted when <see cref="UseKeyring"/> is
        /// <see langword="true"/>.
        /// </summary>
        public string KeyringCollection { get; set; } = "default";
    }
}

using System.Security.Cryptography;

using NextIteration.SpectreConsole.Auth.Encryption;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Encryption;

public sealed class LocalFileCredentialEncryptionTests
{
    [Fact]
    public async Task RoundTrip_Text_ReturnsOriginal()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var cipher = await encryption.EncryptAsync("hello, world!");
        var plain = await encryption.DecryptAsync(cipher);

        Assert.Equal("hello, world!", plain);
    }

    [Fact]
    public async Task RoundTrip_JsonPayload_ReturnsOriginal()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var payload = """{"apiKey":"secret-value","baseUrl":"https://example.com/"}""";
        var cipher = await encryption.EncryptAsync(payload);
        var plain = await encryption.DecryptAsync(cipher);

        Assert.Equal(payload, plain);
    }

    [Fact]
    public async Task RoundTrip_UnicodeContent_ReturnsOriginal()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var payload = "café — 日本語 — 🔐";
        var cipher = await encryption.EncryptAsync(payload);
        var plain = await encryption.DecryptAsync(cipher);

        Assert.Equal(payload, plain);
    }

    [Fact]
    public async Task EncryptAsync_EmptyString_ReturnsEmpty()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var cipher = await encryption.EncryptAsync("");

        Assert.Equal("", cipher);
    }

    [Fact]
    public async Task DecryptAsync_EmptyString_ReturnsEmpty()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var plain = await encryption.DecryptAsync("");

        Assert.Equal("", plain);
    }

    [Fact]
    public async Task DecryptAsync_InvalidBase64_Throws()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => encryption.DecryptAsync("this is not base64!!"));
        Assert.Contains("base64", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DecryptAsync_TamperedCiphertext_ThrowsIntegrityError()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var cipher = await encryption.EncryptAsync("secret message");
        var bytes = Convert.FromBase64String(cipher);

        // Flip a byte inside the ciphertext portion (after the 12-byte nonce
        // and 16-byte tag header).
        bytes[^1] ^= 0xFF;
        var tampered = Convert.ToBase64String(bytes);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => encryption.DecryptAsync(tampered));
        Assert.Contains("integrity", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
    }

    [Fact]
    public async Task DecryptAsync_TamperedTag_ThrowsIntegrityError()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var cipher = await encryption.EncryptAsync("secret message");
        var bytes = Convert.FromBase64String(cipher);

        // Flip a byte inside the 16-byte GCM tag (immediately after the nonce).
        bytes[12] ^= 0x01;
        var tampered = Convert.ToBase64String(bytes);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => encryption.DecryptAsync(tampered));
    }

    [Fact]
    public async Task DecryptAsync_TamperedNonce_ThrowsIntegrityError()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var cipher = await encryption.EncryptAsync("secret message");
        var bytes = Convert.FromBase64String(cipher);

        // Flip a byte inside the 12-byte nonce.
        bytes[0] ^= 0x01;
        var tampered = Convert.ToBase64String(bytes);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => encryption.DecryptAsync(tampered));
    }

    [Fact]
    public async Task DecryptAsync_TruncatedPayload_ThrowsFormatError()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        // "QUJD" = base64 of "ABC" — 3 bytes, way under the 28-byte GCM header.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => encryption.DecryptAsync("QUJD"));
        Assert.Contains("shorter", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EncryptAsync_SamePlaintext_ProducesDifferentCiphertextEachTime()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var a = await encryption.EncryptAsync("identical");
        var b = await encryption.EncryptAsync("identical");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public async Task Encryption_Persists_AcrossInstances()
    {
        using var temp = new TempDir();

        string cipher;
        {
            var first = new LocalFileCredentialEncryption(temp.Path);
            cipher = await first.EncryptAsync("preserved across instance boundary");
        }

        var second = new LocalFileCredentialEncryption(temp.Path);
        var plain = await second.DecryptAsync(cipher);

        Assert.Equal("preserved across instance boundary", plain);
    }

    [Fact]
    public async Task Keystore_IsCreated_OnFirstUse()
    {
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);
        var keystorePath = Path.Combine(temp.Path, ".keystore");

        Assert.False(File.Exists(keystorePath), "keystore should not exist before first encrypt/decrypt");

        _ = await encryption.EncryptAsync("trigger keystore creation");

        Assert.True(File.Exists(keystorePath), "keystore should be created on first encrypt");
    }

    [Fact]
    public async Task Decrypt_WithDifferentKeystore_Throws()
    {
        using var tempA = new TempDir();
        using var tempB = new TempDir();

        var encryptionA = new LocalFileCredentialEncryption(tempA.Path);
        var cipherFromA = await encryptionA.EncryptAsync("bound to keystore A");

        // Simulate an attacker copying the ciphertext but not the keystore.
        var encryptionB = new LocalFileCredentialEncryption(tempB.Path);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => encryptionB.DecryptAsync(cipherFromA));
    }

    [Fact]
    public void Constructor_NullDirectory_Throws()
    {
        // ArgumentException.ThrowIfNullOrWhiteSpace throws
        // ArgumentNullException on null input (a subclass of ArgumentException).
        Assert.ThrowsAny<ArgumentException>(
            () => new LocalFileCredentialEncryption(null!));
    }

    [Fact]
    public void Constructor_EmptyDirectory_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => new LocalFileCredentialEncryption(""));
    }

    [Fact]
    public void Constructor_WhitespaceDirectory_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => new LocalFileCredentialEncryption("   "));
    }

    // =========================
    // Caller-supplied additional entropy
    // =========================

    [Fact]
    public async Task RoundTrip_WithCallerEntropy_ReturnsOriginal()
    {
        using var temp = new TempDir();
        var entropy = "secret-deployment-token"u8.ToArray();
        var encryption = new LocalFileCredentialEncryption(temp.Path, entropy);

        var cipher = await encryption.EncryptAsync("hello with entropy");
        var plain = await encryption.DecryptAsync(cipher);

        Assert.Equal("hello with entropy", plain);
    }

    [Fact]
    public async Task Decrypt_WithDifferentEntropy_Throws()
    {
        using var temp = new TempDir();
        var entropyA = "entropy-alpha"u8.ToArray();
        var encryption = new LocalFileCredentialEncryption(temp.Path, entropyA);
        var cipher = await encryption.EncryptAsync("bound to entropy alpha");

        // Delete the keystore and create a new instance with a different
        // entropy — the new instance will write a fresh keystore and fail
        // to decrypt the old ciphertext.
        File.Delete(Path.Combine(temp.Path, ".keystore"));
        var entropyB = "entropy-bravo"u8.ToArray();
        var wrongEntropy = new LocalFileCredentialEncryption(temp.Path, entropyB);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => wrongEntropy.DecryptAsync(cipher));
        Assert.Contains("integrity check", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Decrypt_WithEntropyAgainstKeystoreWrittenWithout_ThrowsIntegrityError()
    {
        using var temp = new TempDir();

        // Write a keystore with NO entropy, then try to read with entropy
        // set — the derived KEK differs, so loading the keystore fails.
        var noEntropy = new LocalFileCredentialEncryption(temp.Path);
        _ = await noEntropy.EncryptAsync("anything");

        var withEntropy = new LocalFileCredentialEncryption(temp.Path, "new-entropy"u8.ToArray());

        // The very first call will try to load + decrypt the keystore using
        // the wrong KEK.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => withEntropy.EncryptAsync("this triggers keystore load"));
    }

    [Fact]
    public async Task Encryption_IsBackwardCompatible_WhenEntropyNotSupplied()
    {
        // Regression guard: a keystore written by the pre-entropy code path
        // must remain readable when the caller upgrades to the new API but
        // doesn't pass entropy. Since we can't literally run the old code
        // here, this test proves the equivalent contract: omitting entropy
        // (null or empty) produces the same KEK as the pre-entropy default.
        using var temp = new TempDir();

        var withoutEntropy = new LocalFileCredentialEncryption(temp.Path);
        var cipher = await withoutEntropy.EncryptAsync("backward compat check");

        // New instance with explicit null — should read the existing keystore.
        var explicitNull = new LocalFileCredentialEncryption(temp.Path, null);
        Assert.Equal("backward compat check", await explicitNull.DecryptAsync(cipher));

        // Same for an empty array — treated as "no entropy."
        var emptyArray = new LocalFileCredentialEncryption(temp.Path, []);
        Assert.Equal("backward compat check", await emptyArray.DecryptAsync(cipher));
    }

    [Fact]
    public async Task Entropy_Persists_AcrossInstances()
    {
        using var temp = new TempDir();
        var entropy = "stable-deployment-secret"u8.ToArray();

        string cipher;
        {
            var first = new LocalFileCredentialEncryption(temp.Path, entropy);
            cipher = await first.EncryptAsync("survives across instances");
        }

        var second = new LocalFileCredentialEncryption(temp.Path, entropy);
        Assert.Equal("survives across instances", await second.DecryptAsync(cipher));
    }

    [Fact]
    public async Task Entropy_DefensivelyCopied_MutationAfterConstructIsIgnored()
    {
        using var temp = new TempDir();
        var entropy = new byte[] { 1, 2, 3, 4 };
        var encryption = new LocalFileCredentialEncryption(temp.Path, entropy);

        var cipher = await encryption.EncryptAsync("immutable entropy");

        // Mutate the caller's buffer — the stored copy must be unaffected.
        for (var i = 0; i < entropy.Length; i++)
        {
            entropy[i] = 0;
        }

        Assert.Equal("immutable entropy", await encryption.DecryptAsync(cipher));
    }

    [Fact]
    public async Task ConcurrentDecrypt_WithSharedInstance_Succeeds()
    {
        // Lazy<Task<byte[]>> should serialise the first derivation but let
        // subsequent calls complete in parallel once the key is cached.
        using var temp = new TempDir();
        var encryption = new LocalFileCredentialEncryption(temp.Path);

        var ciphers = new List<string>();
        for (var i = 0; i < 5; i++)
        {
            ciphers.Add(await encryption.EncryptAsync($"payload-{i}"));
        }

        var tasks = ciphers.Select(c => encryption.DecryptAsync(c)).ToArray();
        var results = await Task.WhenAll(tasks);

        for (var i = 0; i < results.Length; i++)
        {
            Assert.Equal($"payload-{i}", results[i]);
        }
    }
}

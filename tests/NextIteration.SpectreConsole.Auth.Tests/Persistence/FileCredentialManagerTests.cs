using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Encryption;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence;

public sealed class FileCredentialManagerTests
{
    private static FileCredentialManager CreateManager(string directory, IEnumerable<ICredentialSummaryProvider>? summaryProviders = null)
    {
        var encryption = new LocalFileCredentialEncryption(directory);
        return new FileCredentialManager(encryption, directory, summaryProviders);
    }

    [Fact]
    public void Constructor_NullDirectory_Throws()
    {
        // ArgumentException.ThrowIfNullOrWhiteSpace throws
        // ArgumentNullException on null input (a subclass of ArgumentException).
        var encryption = new LocalFileCredentialEncryption(Path.GetTempPath());
        Assert.ThrowsAny<ArgumentException>(
            () => new FileCredentialManager(encryption, null!));
    }

    [Fact]
    public void Constructor_EmptyDirectory_Throws()
    {
        var encryption = new LocalFileCredentialEncryption(Path.GetTempPath());
        Assert.Throws<ArgumentException>(
            () => new FileCredentialManager(encryption, ""));
    }

    [Fact]
    public async Task AddCredentialAsync_ReturnsGuidAccountId()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var accountId = await manager.AddCredentialAsync(
            providerName: "Adobe",
            accountName: "prod",
            environment: "Production",
            credentialData: "{\"apiKey\":\"x\"}");

        Assert.True(Guid.TryParse(accountId, out _));
    }

    [Fact]
    public async Task AddCredentialAsync_CreatesFileAtExpectedPath()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var expected = Path.Combine(temp.Path, $"adobe_{accountId}.json");
        Assert.True(File.Exists(expected), $"expected credential file at {expected}");
    }

    [Fact]
    public async Task AddCredentialAsync_LowercasesProviderPrefixInFilename()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var upperPath = Path.Combine(temp.Path, $"Adobe_{accountId}.json");
        var lowerPath = Path.Combine(temp.Path, $"adobe_{accountId}.json");
        Assert.True(File.Exists(lowerPath));
        // On case-insensitive filesystems this will also pass — we don't assert !File.Exists(upperPath).
        _ = upperPath;
    }

    [Fact]
    public async Task ListCredentialsAsync_ReturnsAddedCredential()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

        Assert.Single(list);
        Assert.Equal(accountId, list[0].AccountId);
        Assert.Equal("prod", list[0].AccountName);
        Assert.Equal("Adobe", list[0].ProviderName);
        Assert.Equal("Production", list[0].Environment);
        Assert.False(list[0].IsSelected);
    }

    [Fact]
    public async Task ListCredentialsAsync_FiltersByProvider()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        _ = await manager.AddCredentialAsync("Adobe", "a1", "Production", "{}");
        _ = await manager.AddCredentialAsync("Airtable", "b1", "Production", "{}");

        var adobe = (await manager.ListCredentialsAsync("Adobe")).ToList();
        var airtable = (await manager.ListCredentialsAsync("Airtable")).ToList();

        Assert.Single(adobe);
        Assert.Single(airtable);
        Assert.Equal("Adobe", adobe[0].ProviderName);
        Assert.Equal("Airtable", airtable[0].ProviderName);
    }

    [Fact]
    public async Task ListCredentialsAsync_IsCaseInsensitiveOnProviderName()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        _ = await manager.AddCredentialAsync("Adobe", "a1", "Production", "{}");

        var list = (await manager.ListCredentialsAsync("ADOBE")).ToList();

        Assert.Single(list);
    }

    [Fact]
    public async Task ListCredentialsAsync_ReturnsEmpty_WhenNoMatching()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

        Assert.Empty(list);
    }

    [Fact]
    public async Task SelectCredentialAsync_ReturnsTrue_WhenExists()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var selected = await manager.SelectCredentialAsync(accountId);

        Assert.True(selected);
    }

    [Fact]
    public async Task SelectCredentialAsync_ReturnsFalse_WhenNotFound()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var selected = await manager.SelectCredentialAsync(Guid.NewGuid().ToString());

        Assert.False(selected);
    }

    [Fact]
    public async Task SelectCredentialAsync_ShowsSelectedInList()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");
        _ = await manager.SelectCredentialAsync(accountId);

        var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

        Assert.True(list[0].IsSelected);
    }

    [Fact]
    public async Task GetSelectedCredentialAsync_ReturnsDecryptedPayload()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var payload = "{\"apiKey\":\"super-secret\"}";
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", payload);
        _ = await manager.SelectCredentialAsync(accountId);

        var selected = await manager.GetSelectedCredentialAsync("Adobe");

        Assert.Equal(payload, selected);
    }

    [Fact]
    public async Task GetSelectedCredentialAsync_ReturnsNull_WhenNoneSelected()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var selected = await manager.GetSelectedCredentialAsync("Adobe");

        Assert.Null(selected);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsDecryptedPayload_ForExistingAccount()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var payload = "{\"apiKey\":\"super-secret\"}";
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", payload);

        var decrypted = await manager.GetCredentialByIdAsync("Adobe", accountId);

        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsNull_ForUnknownAccountId()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var result = await manager.GetCredentialByIdAsync("Adobe", Guid.NewGuid().ToString());

        Assert.Null(result);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_DoesNotMutateSelection()
    {
        // Regression: the whole reason this method exists is that consumers
        // needed to read non-selected credentials without the old
        // "select + read + restore" dance. Asserting the selection stays
        // put is the core contract.
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var selectedId = await manager.AddCredentialAsync("Adobe", "selected", "Production", "{\"a\":1}");
        var otherId = await manager.AddCredentialAsync("Adobe", "other", "Production", "{\"b\":2}");
        _ = await manager.SelectCredentialAsync(selectedId);

        _ = await manager.GetCredentialByIdAsync("Adobe", otherId);

        var listings = (await manager.ListCredentialsAsync("Adobe")).ToList();
        Assert.True(listings.Single(c => c.AccountId == selectedId).IsSelected);
        Assert.False(listings.Single(c => c.AccountId == otherId).IsSelected);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsNull_WhenProviderMismatches()
    {
        // Cross-provider isolation: an accountId belonging to provider X
        // must not surface when queried against provider Y.
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var adobeId = await manager.AddCredentialAsync("Adobe", "adobe-acct", "Production", "{}");

        var result = await manager.GetCredentialByIdAsync("Airtable", adobeId);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_WithInvalidProviderName_Throws()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => manager.GetCredentialByIdAsync("   ", Guid.NewGuid().ToString()));
    }

    [Fact]
    public async Task GetCredentialByIdAsync_WithInvalidAccountId_Throws()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => manager.GetCredentialByIdAsync("Adobe", "   "));
    }

    [Fact]
    public async Task DeleteCredentialAsync_RemovesFile()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");
        var filePath = Path.Combine(temp.Path, $"adobe_{accountId}.json");
        Assert.True(File.Exists(filePath));

        var deleted = await manager.DeleteCredentialAsync(accountId);

        Assert.True(deleted);
        Assert.False(File.Exists(filePath));
    }

    [Fact]
    public async Task DeleteCredentialAsync_ClearsSelection_IfItWasSelected()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");
        _ = await manager.SelectCredentialAsync(accountId);

        _ = await manager.DeleteCredentialAsync(accountId);

        Assert.Null(await manager.GetSelectedCredentialAsync("Adobe"));
    }

    [Fact]
    public async Task DeleteCredentialAsync_ReturnsFalse_WhenNotFound()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var deleted = await manager.DeleteCredentialAsync(Guid.NewGuid().ToString());

        Assert.False(deleted);
    }

    [Fact]
    public async Task GetProviderNamesAsync_ReturnsDistinctProviders()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);
        _ = await manager.AddCredentialAsync("Adobe", "a1", "Production", "{}");
        _ = await manager.AddCredentialAsync("Adobe", "a2", "Sandbox", "{}");
        _ = await manager.AddCredentialAsync("Airtable", "b1", "Production", "{}");

        var names = (await manager.GetProviderNamesAsync()).ToList();

        Assert.Equal(2, names.Count);
        Assert.Contains("Adobe", names);
        Assert.Contains("Airtable", names);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("../etc/passwd")]
    [InlineData("..\\windows\\system32")]
    [InlineData("pro*vider")]
    [InlineData("pro?vider")]
    [InlineData("pro/vider")]
    [InlineData("pro\\vider")]
    [InlineData("pro vider")]
    [InlineData("pro:vider")]
    [InlineData("proπvider")]
    public async Task AddCredentialAsync_InvalidProviderName_Throws(string providerName)
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        await Assert.ThrowsAsync<ArgumentException>(
            () => manager.AddCredentialAsync(providerName, "name", "Production", "{}"));
    }

    [Theory]
    [InlineData("Adobe")]
    [InlineData("my-provider")]
    [InlineData("my.provider")]
    [InlineData("my_provider")]
    [InlineData("Provider123")]
    [InlineData("ABC")]
    public async Task AddCredentialAsync_ValidProviderName_Succeeds(string providerName)
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var accountId = await manager.AddCredentialAsync(providerName, "name", "Production", "{}");

        Assert.True(Guid.TryParse(accountId, out _));
    }

    [Fact]
    public async Task AddCredentialAsync_SetsCredentialFileMode0600_OnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // Unix-only assertion.
        }

        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var filePath = Path.Combine(temp.Path, $"adobe_{accountId}.json");
        var mode = File.GetUnixFileMode(filePath);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
    }

    [Fact]
    public async Task ListCredentialsAsync_IncludesDisplayFields_FromSummaryProvider()
    {
        using var temp = new TempDir();
        var summary = new FakeAdobeSummaryProvider();
        var manager = CreateManager(temp.Path, [summary]);

        _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"abcd1234\"}");
        var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

        Assert.Single(list);
        var fields = list[0].DisplayFields;
        Assert.Single(fields);
        Assert.Equal("Fingerprint", fields[0].Key);
        Assert.Equal("abcd1234", fields[0].Value);
    }

    [Fact]
    public async Task ListCredentialsAsync_LeavesDisplayFieldsEmpty_WhenNoProviderRegistered()
    {
        using var temp = new TempDir();
        var manager = CreateManager(temp.Path);

        _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");
        var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

        Assert.Empty(list[0].DisplayFields);
    }

    [Fact]
    public async Task Credential_Persists_AcrossManagerInstances()
    {
        using var temp = new TempDir();

        string accountId;
        {
            var first = CreateManager(temp.Path);
            accountId = await first.AddCredentialAsync("Adobe", "prod", "Production", "{\"key\":\"v\"}");
            _ = await first.SelectCredentialAsync(accountId);
        }

        var second = CreateManager(temp.Path);
        var list = (await second.ListCredentialsAsync("Adobe")).ToList();

        Assert.Single(list);
        Assert.Equal(accountId, list[0].AccountId);
        Assert.True(list[0].IsSelected);
        Assert.Equal("{\"key\":\"v\"}", await second.GetSelectedCredentialAsync("Adobe"));
    }

    /// <summary>
    /// Minimal summary provider used only to verify that
    /// <see cref="FileCredentialManager.ListCredentialsAsync"/> routes
    /// decrypted data through the registered projection. Returns the raw
    /// payload under a single 'Fingerprint' column without any parsing.
    /// </summary>
    private sealed class FakeAdobeSummaryProvider : ICredentialSummaryProvider
    {
        public string ProviderName => "Adobe";

        public IReadOnlyList<KeyValuePair<string, string>> GetDisplayFields(string decryptedCredentialJson)
        {
            // Pull the apiKey value back out of the minimal payload the test writes.
            // Keeping this parser-free so the test isn't coupled to System.Text.Json behaviour.
            const string token = "\"apiKey\":\"";
            var start = decryptedCredentialJson.IndexOf(token, StringComparison.Ordinal);
            if (start < 0) return [];
            start += token.Length;
            var end = decryptedCredentialJson.IndexOf('"', start);
            var value = decryptedCredentialJson[start..end];
            return [new("Fingerprint", value)];
        }
    }
}

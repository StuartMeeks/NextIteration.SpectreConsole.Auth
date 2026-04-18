using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Persistence.Keychain;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence;

/// <summary>
/// Integration tests against the real macOS Keychain. Every test is gated on
/// <see cref="OperatingSystem.IsMacOS"/> and early-returns (passing trivially)
/// on Windows or Linux because the P/Invoke surface targets
/// Security.framework exclusively.
/// </summary>
/// <remarks>
/// Each test uses a unique app-identifier per run (guid-suffixed) so
/// concurrent test runs and stale items from a previous run don't collide.
/// Best-effort cleanup runs on disposal but isn't load-bearing — the
/// unique-identifier discipline is what keeps tests isolated.
/// </remarks>
[SupportedOSPlatform("macos")]
public sealed class KeychainCredentialManagerTests : IDisposable
{
    private readonly string _appIdentifier;
    private readonly bool _skip;

    public KeychainCredentialManagerTests()
    {
        _skip = !OperatingSystem.IsMacOS();
        _appIdentifier = $"test.nextiteration.sca.{Guid.NewGuid():N}";
    }

    public void Dispose()
    {
        // Best-effort cleanup: delete everything this test added.
        if (_skip) return;
        TryCleanup();
    }

    private void TryCleanup()
    {
#pragma warning disable CA1416 // Validated by _skip check in Dispose().
        try
        {
            var manager = new KeychainCredentialManager(_appIdentifier);
            foreach (var provider in manager.GetProviderNamesAsync().GetAwaiter().GetResult())
            {
                foreach (var summary in manager.ListCredentialsAsync(provider).GetAwaiter().GetResult())
                {
                    _ = manager.DeleteCredentialAsync(summary.AccountId).GetAwaiter().GetResult();
                }
            }
        }
        catch
        {
            // Swallow — cleanup is a nicety, not a contract.
        }
#pragma warning restore CA1416
    }

    private KeychainCredentialManager NewManager(IEnumerable<ICredentialSummaryProvider>? summary = null)
    {
#pragma warning disable CA1416 // Validated by _skip check in each test.
        return new KeychainCredentialManager(_appIdentifier, summary);
#pragma warning restore CA1416
    }

    [Fact]
    public async Task AddCredentialAsync_ReturnsGuidAccountId()
    {
        if (_skip) return;
        var manager = NewManager();

        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        Assert.True(Guid.TryParse(accountId, out _));
    }

    [Fact]
    public async Task ListCredentialsAsync_ReturnsAddedCredential()
    {
        if (_skip) return;
        var manager = NewManager();
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
        if (_skip) return;
        var manager = NewManager();
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
    public async Task SelectAndGetSelected_RoundTripsDecryptedPayload()
    {
        if (_skip) return;
        var manager = NewManager();
        var payload = "{\"apiKey\":\"super-secret\"}";
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", payload);

        Assert.True(await manager.SelectCredentialAsync(accountId));
        var selected = await manager.GetSelectedCredentialAsync("Adobe");

        Assert.Equal(payload, selected);
    }

    [Fact]
    public async Task SelectCredentialAsync_ReturnsFalse_WhenNotFound()
    {
        if (_skip) return;
        var manager = NewManager();

        var selected = await manager.SelectCredentialAsync(Guid.NewGuid().ToString());

        Assert.False(selected);
    }

    [Fact]
    public async Task GetSelectedCredentialAsync_ReturnsNull_WhenNoneSelected()
    {
        if (_skip) return;
        var manager = NewManager();
        _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var selected = await manager.GetSelectedCredentialAsync("Adobe");

        Assert.Null(selected);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsDecryptedPayload_ForExistingAccount()
    {
        if (_skip) return;
        var manager = NewManager();
        var payload = "{\"apiKey\":\"super-secret\"}";
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", payload);

        var decrypted = await manager.GetCredentialByIdAsync("Adobe", accountId);

        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_ReturnsNull_ForUnknownAccountId()
    {
        if (_skip) return;
        var manager = NewManager();
        _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var result = await manager.GetCredentialByIdAsync("Adobe", Guid.NewGuid().ToString());

        Assert.Null(result);
    }

    [Fact]
    public async Task GetCredentialByIdAsync_DoesNotMutateSelection()
    {
        if (_skip) return;
        var manager = NewManager();
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
        if (_skip) return;
        var manager = NewManager();
        var adobeId = await manager.AddCredentialAsync("Adobe", "adobe-acct", "Production", "{}");

        var result = await manager.GetCredentialByIdAsync("Airtable", adobeId);

        Assert.Null(result);
    }

    [Fact]
    public async Task DeleteCredentialAsync_RemovesCredential()
    {
        if (_skip) return;
        var manager = NewManager();
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

        var deleted = await manager.DeleteCredentialAsync(accountId);
        var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

        Assert.True(deleted);
        Assert.Empty(list);
    }

    [Fact]
    public async Task DeleteCredentialAsync_ClearsSelection_IfItWasSelected()
    {
        if (_skip) return;
        var manager = NewManager();
        var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");
        _ = await manager.SelectCredentialAsync(accountId);

        _ = await manager.DeleteCredentialAsync(accountId);

        Assert.Null(await manager.GetSelectedCredentialAsync("Adobe"));
    }

    [Fact]
    public async Task DeleteCredentialAsync_ReturnsFalse_WhenNotFound()
    {
        if (_skip) return;
        var manager = NewManager();

        var deleted = await manager.DeleteCredentialAsync(Guid.NewGuid().ToString());

        Assert.False(deleted);
    }

    [Fact]
    public async Task GetProviderNamesAsync_ReturnsDistinctProviders()
    {
        if (_skip) return;
        var manager = NewManager();
        _ = await manager.AddCredentialAsync("Adobe", "a1", "Production", "{}");
        _ = await manager.AddCredentialAsync("Adobe", "a2", "Sandbox", "{}");
        _ = await manager.AddCredentialAsync("Airtable", "b1", "Production", "{}");

        var names = (await manager.GetProviderNamesAsync()).ToList();

        Assert.Equal(2, names.Count);
        Assert.Contains("Adobe", names);
        Assert.Contains("Airtable", names);
    }

    [Fact]
    public async Task Credentials_AreIsolated_ByAppIdentifier()
    {
        if (_skip) return;

        // Create a neighbour app that shouldn't see our items.
        var neighbourIdentifier = $"test.nextiteration.sca.neighbour.{Guid.NewGuid():N}";
#pragma warning disable CA1416
        var neighbour = new KeychainCredentialManager(neighbourIdentifier);
#pragma warning restore CA1416
        try
        {
            var us = NewManager();
            _ = await us.AddCredentialAsync("Adobe", "ours", "Production", "{}");

            var neighbourList = (await neighbour.ListCredentialsAsync("Adobe")).ToList();
            Assert.Empty(neighbourList);
        }
        finally
        {
            // Clean up neighbour.
            foreach (var p in await neighbour.GetProviderNamesAsync())
            {
                foreach (var s in await neighbour.ListCredentialsAsync(p))
                {
                    _ = await neighbour.DeleteCredentialAsync(s.AccountId);
                }
            }
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("../etc/passwd")]
    [InlineData("pro*vider")]
    [InlineData("pro vider")]
    public async Task AddCredentialAsync_InvalidProviderName_Throws(string providerName)
    {
        if (_skip) return;
        var manager = NewManager();

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => manager.AddCredentialAsync(providerName, "name", "Production", "{}"));
    }

    [Fact]
    public void Constructor_NullAppIdentifier_Throws()
    {
        if (_skip) return;
#pragma warning disable CA1416
        Assert.ThrowsAny<ArgumentException>(() => new KeychainCredentialManager(null!));
#pragma warning restore CA1416
    }

    [Fact]
    public void Constructor_EmptyAppIdentifier_Throws()
    {
        if (_skip) return;
#pragma warning disable CA1416
        Assert.ThrowsAny<ArgumentException>(() => new KeychainCredentialManager(""));
#pragma warning restore CA1416
    }

    [Fact]
    public async Task ListCredentialsAsync_IncludesDisplayFields_FromSummaryProvider()
    {
        if (_skip) return;
        var summaryProvider = new FakeAdobeSummaryProvider();
        var manager = NewManager([summaryProvider]);

        _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"xyz\"}");
        var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

        Assert.Single(list);
        Assert.Single(list[0].DisplayFields);
        Assert.Equal("Fingerprint", list[0].DisplayFields[0].Key);
        Assert.Equal("xyz", list[0].DisplayFields[0].Value);
    }

    private sealed class FakeAdobeSummaryProvider : ICredentialSummaryProvider
    {
        public string ProviderName => "Adobe";

        public IReadOnlyList<KeyValuePair<string, string>> GetDisplayFields(string decryptedCredentialJson)
        {
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

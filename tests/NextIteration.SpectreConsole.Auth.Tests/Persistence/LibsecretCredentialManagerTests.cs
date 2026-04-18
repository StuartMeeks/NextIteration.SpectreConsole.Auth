using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Persistence.Libsecret;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence;

/// <summary>
/// Integration tests against the real Linux Secret Service (libsecret).
/// Every test is gated on <see cref="OperatingSystem.IsLinux"/> and on a
/// best-effort "is the Secret Service daemon actually reachable" probe.
/// Linux environments without a running keyring daemon (minimal containers,
/// SSH-only servers, CI without the workflow setup) cause the probe to
/// return false and tests pass vacuously.
/// </summary>
/// <remarks>
/// <para>
/// Each test uses a unique app identifier per run (guid-suffixed) so
/// stale items from a previous failed run don't collide.
/// </para>
/// <para>
/// Tests target the <c>"session"</c> collection (in-memory, always present
/// on a running daemon). The default <c>"default"</c>/login collection
/// requires provisioning a <c>login.keyring</c> file on disk, which fresh
/// CI runners don't have — targeting <c>"session"</c> side-steps that
/// without any CI bootstrap gymnastics.
/// </para>
/// </remarks>
[SupportedOSPlatform("linux")]
public sealed class LibsecretCredentialManagerTests : IDisposable
{
    private const string TestCollection = "session";

    private readonly string _appIdentifier;
    private readonly bool _skip;

    public LibsecretCredentialManagerTests()
    {
        _appIdentifier = $"test.nextiteration.sca.{Guid.NewGuid():N}";
        _skip = !OperatingSystem.IsLinux() || !IsSecretServiceAvailable();
    }

    /// <summary>
    /// Best-effort probe: try a store + clear against the session collection
    /// and treat any exception as "Secret Service isn't available." A bare
    /// search doesn't exercise the collection write path, so we do a real
    /// round-trip. Not running on Linux counts as unavailable too so the
    /// test class compiles clean on any platform.
    /// </summary>
    private static bool IsSecretServiceAvailable()
    {
        if (!OperatingSystem.IsLinux()) return false;
        try
        {
#pragma warning disable CA1416
            var probe = new LibsecretCredentialManager(
                $"probe.{Guid.NewGuid():N}",
                collection: TestCollection);
            var id = probe.AddCredentialAsync("Probe", "probe", "Probe", "{}").GetAwaiter().GetResult();
            _ = probe.DeleteCredentialAsync(id).GetAwaiter().GetResult();
#pragma warning restore CA1416
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_skip) return;
        TryCleanup();
    }

    private void TryCleanup()
    {
#pragma warning disable CA1416
        try
        {
            var manager = new LibsecretCredentialManager(_appIdentifier, collection: TestCollection);
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

    private LibsecretCredentialManager NewManager(IEnumerable<ICredentialSummaryProvider>? summary = null)
    {
#pragma warning disable CA1416
        return new LibsecretCredentialManager(_appIdentifier, summary, TestCollection);
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

        var neighbourIdentifier = $"test.nextiteration.sca.neighbour.{Guid.NewGuid():N}";
#pragma warning disable CA1416
        var neighbour = new LibsecretCredentialManager(neighbourIdentifier, collection: TestCollection);
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
        if (!OperatingSystem.IsLinux()) return;
#pragma warning disable CA1416
        Assert.ThrowsAny<ArgumentException>(() => new LibsecretCredentialManager(null!));
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

using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Persistence.Keychain;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence
{
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

        // Reported as a real skip rather than an early return, so a non-macOS run
        // shows up as skipped instead of silently passing.
        private const string SkipReason = "macOS is required for the Keychain backend.";

        public KeychainCredentialManagerTests()
        {
            _skip = !OperatingSystem.IsMacOS();
            _appIdentifier = $"test.nextiteration.sca.{Guid.NewGuid():N}";
        }

        public void Dispose()
        {
            // Best-effort cleanup: delete everything this test added. Not a skip point —
            // Dispose runs after a skipped test too, and throwing the dynamic-skip
            // exception here surfaces as a failure rather than a skip.
            if (_skip)
            {
                return;
            }

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

        private KeychainCredentialManager NewManager(IEnumerable<ICredentialSummaryProvider>? summary = null) =>
#pragma warning disable CA1416 // Validated by _skip check in each test.
            new(_appIdentifier, summary);
#pragma warning restore CA1416


        [Fact]
        public async Task ExportCredentialsAsync_ReturnsDecryptedPayloadAndSelection()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"secret\"}");
            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.SelectCredentialAsync(id)));

            var adobe = Assert.Single(await RetryHelper.UntilAsync(() => manager.ExportCredentialsAsync(), r => r.Count == 1));
            Assert.Equal(id, adobe.AccountId);
            Assert.Equal("prod", adobe.AccountName);
            Assert.Equal("Adobe", adobe.ProviderName);
            Assert.Equal("Production", adobe.Environment);
            Assert.Equal("{\"apiKey\":\"secret\"}", adobe.CredentialData);
            Assert.True(adobe.IsSelected);

            // Guards the skip added for #42 on the backend where it is reachable: a
            // readable credential must still be exported, and carry its real payload
            // rather than the empty string the old ternary substituted.
            Assert.NotEqual(string.Empty, adobe.CredentialData);
        }

        [Fact]
        public async Task RestoreCredentialAsync_PreservesAccountIdAndSelection()
        {
            // The macOS Keychain assigns its own creation date, so CreatedAt is
            // intentionally not asserted here (see RestoreCredentialAsync remarks).
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"secret\"}");
            _ = await manager.SelectCredentialAsync(id);
            var exported = Assert.Single(await RetryHelper.UntilAsync(() => manager.ExportCredentialsAsync(), r => r.Count == 1));

            // Simulate an import: drop it, then restore from the export record.
            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.DeleteCredentialAsync(id)));
            await manager.RestoreCredentialAsync(exported);

            // Retry on the property actually being asserted, not just the count. The
            // selection is a separate store item written moments earlier by
            // RestoreCredentialAsync, so the credential can become visible before the
            // selection does — and the count-only predicate let the assertions run against
            // a half-visible store, which is what flaked on the macOS runner (#61).
            var restored = Assert.Single(await RetryHelper.UntilAsync(
                () => manager.ExportCredentialsAsync(),
                r => r.Count == 1 && r[0].IsSelected));
            Assert.Equal(id, restored.AccountId);
            Assert.True(restored.IsSelected);
            Assert.Equal("{\"apiKey\":\"secret\"}", await manager.GetSelectedCredentialAsync("Adobe"));
        }

        [Fact]
        public async Task AddCredentialAsync_ReturnsGuidAccountId()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();

            var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            Assert.True(Guid.TryParse(accountId, out _));
        }

        [Fact]
        public async Task ListCredentialsAsync_ReturnsAddedCredential()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

            var credential = Assert.Single(list);
            Assert.Equal(accountId, credential.AccountId);
            Assert.Equal("prod", credential.AccountName);
            Assert.Equal("Adobe", credential.ProviderName);
            Assert.Equal("Production", credential.Environment);
            Assert.False(credential.IsSelected);
        }

        [Fact]
        public async Task ListCredentialsAsync_FiltersByProvider()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            _ = await manager.AddCredentialAsync("Adobe", "a1", "Production", "{}");
            _ = await manager.AddCredentialAsync("Airtable", "b1", "Production", "{}");

            var adobe = (await manager.ListCredentialsAsync("Adobe")).ToList();
            var airtable = (await manager.ListCredentialsAsync("Airtable")).ToList();

            var adobeCredential = Assert.Single(adobe);
            var airtableCredential = Assert.Single(airtable);
            Assert.Equal("Adobe", adobeCredential.ProviderName);
            Assert.Equal("Airtable", airtableCredential.ProviderName);
        }

        [Fact]
        public async Task SelectAndGetSelected_RoundTripsDecryptedPayload()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var payload = "{\"apiKey\":\"super-secret\"}";
            var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", payload);

            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.SelectCredentialAsync(accountId)));
            var selected = await manager.GetSelectedCredentialAsync("Adobe");

            Assert.Equal(payload, selected);
        }

        [Fact]
        public async Task SelectCredentialAsync_ReturnsFalse_WhenNotFound()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();

            var selected = await manager.SelectCredentialAsync(Guid.NewGuid().ToString());

            Assert.False(selected);
        }

        [Fact]
        public async Task GetSelectedCredentialAsync_ReturnsNull_WhenNoneSelected()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            var selected = await manager.GetSelectedCredentialAsync("Adobe");

            Assert.Null(selected);
        }

        [Fact]
        public async Task GetCredentialByIdAsync_ReturnsDecryptedPayload_ForExistingAccount()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var payload = "{\"apiKey\":\"super-secret\"}";
            var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", payload);

            var decrypted = await manager.GetCredentialByIdAsync("Adobe", accountId);

            Assert.Equal(payload, decrypted);
        }

        [Fact]
        public async Task GetCredentialByIdAsync_ReturnsNull_ForUnknownAccountId()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            var result = await manager.GetCredentialByIdAsync("Adobe", Guid.NewGuid().ToString());

            Assert.Null(result);
        }

        [Fact]
        public async Task GetCredentialByIdAsync_DoesNotMutateSelection()
        {
            Assert.SkipWhen(_skip, SkipReason);

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
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var adobeId = await manager.AddCredentialAsync("Adobe", "adobe-acct", "Production", "{}");

            var result = await manager.GetCredentialByIdAsync("Airtable", adobeId);

            Assert.Null(result);
        }

        [Fact]
        public async Task DeleteCredentialAsync_RemovesCredential()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            var deleted = await RetryHelper.UntilTrueAsync(() => manager.DeleteCredentialAsync(accountId));
            var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

            Assert.True(deleted);
            Assert.Empty(list);
        }

        [Fact]
        public async Task DeleteCredentialAsync_ClearsSelection_IfItWasSelected()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");
            _ = await manager.SelectCredentialAsync(accountId);

            var unrelated = await manager.AddCredentialAsync("Airtable", "main", "Production", "{}");
            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.SelectCredentialAsync(unrelated)));

            _ = await RetryHelper.UntilTrueAsync(() => manager.DeleteCredentialAsync(accountId));

            // Weaker than its file and libsecret counterparts by necessity: the selection
            // is a separate keychain item and this assertion returns null once the
            // credential is gone regardless of whether that item was cleared, so it cannot
            // distinguish the two (#50). Asserting on the item itself would need a
            // Security.framework query from the test. What the unrelated-provider check
            // below does catch is over-broad clearing, which is the more likely defect.
            Assert.Null(await manager.GetSelectedCredentialAsync("Adobe"));
            Assert.Equal("{}", await manager.GetSelectedCredentialAsync("Airtable"));
        }

        [Fact]
        public async Task DeleteCredentialAsync_ReturnsFalse_WhenNotFound()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();

            var deleted = await manager.DeleteCredentialAsync(Guid.NewGuid().ToString());

            Assert.False(deleted);
        }

        [Fact]
        public async Task GetProviderNamesAsync_ReturnsDistinctProviders()
        {
            Assert.SkipWhen(_skip, SkipReason);

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
            Assert.SkipWhen(_skip, SkipReason);

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
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();

            await Assert.ThrowsAnyAsync<ArgumentException>(
                () => manager.AddCredentialAsync(providerName, "name", "Production", "{}"));
        }

        [Fact]
        public void Constructor_NullAppIdentifier_Throws()
        {
            Assert.SkipWhen(_skip, SkipReason);
#pragma warning disable CA1416
            Assert.ThrowsAny<ArgumentException>(() => new KeychainCredentialManager(null!));
#pragma warning restore CA1416
        }

        [Fact]
        public void Constructor_EmptyAppIdentifier_Throws()
        {
            Assert.SkipWhen(_skip, SkipReason);
#pragma warning disable CA1416
            Assert.ThrowsAny<ArgumentException>(() => new KeychainCredentialManager(""));
#pragma warning restore CA1416
        }

        [Fact]
        public async Task ListCredentialsAsync_IncludesDisplayFields_FromSummaryProvider()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var summaryProvider = new FakeAdobeSummaryProvider();
            var manager = NewManager([summaryProvider]);

            _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"xyz\"}");
            var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

            var credential = Assert.Single(list);
            var field = Assert.Single(credential.DisplayFields);
            Assert.Equal("Fingerprint", field.Key);
            Assert.Equal("xyz", field.Value);

            // The data loaded, so the row is not flagged. The false branch needs a
            // load failure, which cannot be forced through the static P/Invoke
            // surface — see #42.
            Assert.True(credential.IsDecryptable);
        }

        [Fact]
        [SupportedOSPlatform("macos")]
        public async Task SelectCredentialAsync_ReplacingAnExistingSelection_LeavesExactlyOneSelected()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var prod = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"PROD\"}");
            var sandbox = await manager.AddCredentialAsync("Adobe", "sandbox", "Sandbox", "{\"k\":\"SANDBOX\"}");

            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.SelectCredentialAsync(prod)));
            Assert.Equal("{\"k\":\"PROD\"}", await manager.GetSelectedCredentialAsync("Adobe"));

            // The second selection for the same provider takes the update-an-existing-record
            // branch, which no test reached before (#51) -- on this backend that is the
            // difference between writing a new item and updating the one already there.
            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.SelectCredentialAsync(sandbox)));
            Assert.Equal("{\"k\":\"SANDBOX\"}", await manager.GetSelectedCredentialAsync("Adobe"));

            var listed = await RetryHelper.UntilAsync(
                () => manager.ListCredentialsAsync("Adobe"),
                r => r.Count() == 2 && r.Count(c => c.IsSelected) == 1);

            Assert.True(listed.Single(c => c.AccountId == sandbox).IsSelected);
            Assert.False(listed.Single(c => c.AccountId == prod).IsSelected);
        }

        private sealed class FakeAdobeSummaryProvider : ICredentialSummaryProvider
        {
            public string ProviderName => "Adobe";

            public IReadOnlyList<KeyValuePair<string, string>> GetDisplayFields(string decryptedCredentialJson)
            {
                const string token = "\"apiKey\":\"";
                var start = decryptedCredentialJson.IndexOf(token, StringComparison.Ordinal);
                if (start < 0)
                {
                    return [];
                }

                start += token.Length;
                var end = decryptedCredentialJson.IndexOf('"', start);
                var value = decryptedCredentialJson[start..end];
                return [new("Fingerprint", value)];
            }
        }
    }
}

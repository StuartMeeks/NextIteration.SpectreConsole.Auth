using System.Runtime.Versioning;

using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Persistence.Libsecret;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence
{
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

        // Reported as a real skip rather than an early return, so an environment
        // without a Secret Service shows up as skipped instead of silently passing.
        private const string SkipReason =
            "Linux with a reachable Secret Service daemon is required; see the libsecret setup in ci.yml.";

        private readonly string _appIdentifier;
        private readonly bool _skip;

        public LibsecretCredentialManagerTests()
        {
            _appIdentifier = $"test.nextiteration.sca.{Guid.NewGuid():N}";
            _skip = !OperatingSystem.IsLinux() || !IsSecretServiceAvailable();
        }

        /// <summary>
        /// Probes whether a Secret Service daemon is reachable, using the interop layer
        /// directly and touching <b>no</b> part of <see cref="LibsecretCredentialManager"/>.
        /// </summary>
        /// <remarks>
        /// This deliberately does not go through the manager. The previous probe performed
        /// a real store + clear via <c>AddCredentialAsync</c>/<c>DeleteCredentialAsync</c>
        /// inside a catch-all, so a regression in the very code these tests exist to cover
        /// made the probe throw, set <c>_skip</c>, and turn all ~20 tests into silent
        /// no-ops that still reported as passing (#46). The more broken the backend, the
        /// quieter the suite.
        /// <para>
        /// A read-only search against an attribute set that cannot match anything is enough
        /// to tell "no daemon" from "daemon present", and it stays true regardless of what
        /// the manager does.
        /// </para>
        /// </remarks>
        private static bool IsSecretServiceAvailable()
        {
            if (!OperatingSystem.IsLinux())
            {
                return false;
            }

            try
            {
                var attrs = LibsecretInterop.NewAttributes(new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    // A value no stored item can carry, so the search matches nothing and
                    // the call is purely an availability check.
                    ["nextIteration.sca.probe"] = Guid.NewGuid().ToString("N"),
                });

                try
                {
                    var list = LibsecretInterop.secret_password_searchv_sync(
                        IntPtr.Zero, attrs, LibsecretInterop.SecretSearchAll, IntPtr.Zero, out var error);

                    if (error != IntPtr.Zero)
                    {
                        LibsecretInterop.g_error_free(error);
                        return false;
                    }

                    if (list != IntPtr.Zero)
                    {
                        LibsecretInterop.g_list_free(list);
                    }

                    return true;
                }
                finally
                {
                    LibsecretInterop.g_hash_table_unref(attrs);
                }
            }
            catch (DllNotFoundException)
            {
                // libsecret-1.so.0 not installed.
                return false;
            }
            catch (EntryPointNotFoundException)
            {
                return false;
            }
        }

        public void Dispose()
        {
            if (_skip)
            {
                return;
            }

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

        private LibsecretCredentialManager NewManager(IEnumerable<ICredentialSummaryProvider>? summary = null) =>
#pragma warning disable CA1416
            new(_appIdentifier, summary, TestCollection);
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
        }

        [Fact]
        public async Task RestoreCredentialAsync_PreservesAccountIdCreatedAtAndSelection()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"secret\"}");
            _ = await manager.SelectCredentialAsync(id);
            var exported = Assert.Single(await RetryHelper.UntilAsync(() => manager.ExportCredentialsAsync(), r => r.Count == 1));

            // Simulate an import: drop it, then restore from the export record.
            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.DeleteCredentialAsync(id)));
            await manager.RestoreCredentialAsync(exported);

            var restored = Assert.Single(await RetryHelper.UntilAsync(() => manager.ExportCredentialsAsync(), r => r.Count == 1));
            Assert.Equal(id, restored.AccountId);
            Assert.Equal(exported.CreatedAt, restored.CreatedAt); // libsecret preserves it via attribute
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

            Assert.Single(adobe);
            Assert.Single(airtable);
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

            // GetSelectedCredentialAsync returns null once the credential is gone whether
            // or not the selection was cleared, so it cannot distinguish the two (#50).
            // The selection is its own keyring item, so assert on that directly.
            var stale = LibsecretInterop.NewAttributes(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["nextIteration.sca.app"] = _appIdentifier,
                ["nextIteration.sca.kind"] = "selection",
                ["nextIteration.sca.provider"] = "Adobe",
            });
            try
            {
                var found = LibsecretInterop.secret_password_searchv_sync(
                    IntPtr.Zero, stale, LibsecretInterop.SecretSearchAll, IntPtr.Zero, out var error);
                Assert.Equal(IntPtr.Zero, error);
                Assert.Equal(IntPtr.Zero, found);
            }
            finally
            {
                LibsecretInterop.g_hash_table_unref(stale);
            }

            Assert.Null(await manager.GetSelectedCredentialAsync("Adobe"));

            // An unrelated provider's selection must survive the delete.
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
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();

            await Assert.ThrowsAnyAsync<ArgumentException>(
                () => manager.AddCredentialAsync(providerName, "name", "Production", "{}"));
        }

        [Fact]
        public void Constructor_NullAppIdentifier_Throws()
        {
            if (!OperatingSystem.IsLinux())
            {
                return;
            }
#pragma warning disable CA1416
            Assert.ThrowsAny<ArgumentException>(() => new LibsecretCredentialManager(null!));
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

            // The secret loaded, so the row is not flagged. The false branch needs a
            // secret that fails to load, which cannot be forced through the static
            // P/Invoke surface — see #42.
            Assert.True(credential.IsDecryptable);
        }

        [Fact]
        [SupportedOSPlatform("linux")]
        public async Task ListCredentialsAsync_NoSummaryProvider_ReportsDecryptable()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager(); // no summary provider

            _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"xyz\"}");
            var list = (await manager.ListCredentialsAsync("Adobe")).ToList();

            // No summary provider means the secret is never requested, so there is
            // nothing to report and the flag stays true — the same meaning the file
            // backend gives it.
            Assert.True(Assert.Single(list).IsDecryptable);
        }

        [Fact]
        [SupportedOSPlatform("linux")]
        public async Task ExportCredentialsAsync_CarriesTheRealSecret()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"xyz\"}");

            // Retried like every sibling export test: AddCredentialAsync confirms
            // visibility via secret_password_lookupv on the full attribute key, which
            // is a different query path from the export's secret_password_searchv on
            // (app, kind) — so being visible to the lookup does not imply being
            // visible to the search yet.
            var exported = Assert.Single(
                await RetryHelper.UntilAsync(() => manager.ExportCredentialsAsync(), r => r.Count == 1));

            // Guards the skip added for #42: a readable credential must still be
            // exported, and with its real payload rather than an empty string.
            Assert.Equal(id, exported.AccountId);
            Assert.Equal("{\"apiKey\":\"xyz\"}", exported.CredentialData);
            Assert.NotEqual(string.Empty, exported.CredentialData);
        }

        [Theory]
        [InlineData("Adobe")]
        [InlineData("adobe")]
        [InlineData("ADOBE")]
        [SupportedOSPlatform("linux")]
        public async Task ProviderLookups_AreCaseInsensitive(string spelling)
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"v\"}");
            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.SelectCredentialAsync(id)));

            // The OS backends keyed every lookup on the caller's exact spelling, so a
            // consumer that worked against the file backend returned nothing here (#49).
            var listed = Assert.Single(
                await RetryHelper.UntilAsync(() => manager.ListCredentialsAsync(spelling), r => r.Count() == 1));
            Assert.Equal(id, listed.AccountId);
            Assert.Equal("{\"k\":\"v\"}", await manager.GetSelectedCredentialAsync(spelling));
            Assert.Equal("{\"k\":\"v\"}", await manager.GetCredentialByIdAsync(spelling, id));
        }

        [Fact]
        [SupportedOSPlatform("linux")]
        public async Task DeleteCredentialAsync_ReportsTrueOnlyWhenTheItemIsActuallyGone()
        {
            Assert.SkipWhen(_skip, SkipReason);

            var manager = NewManager();
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"v\"}");

            // A successful delete must both report true and leave nothing behind. The
            // gboolean from secret_password_clearv_sync used to be discarded, so this
            // returned true unconditionally (#45); threading it through is what these
            // assertions now pin.
            Assert.True(await RetryHelper.UntilTrueAsync(() => manager.DeleteCredentialAsync(id)));
            Assert.Empty(await RetryHelper.UntilAsync(() => manager.ListCredentialsAsync("Adobe"), r => !r.Any()));

            // Deleting it again must report false, not a second success.
            Assert.False(await manager.DeleteCredentialAsync(id));
        }

        [Fact]
        [SupportedOSPlatform("linux")]
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

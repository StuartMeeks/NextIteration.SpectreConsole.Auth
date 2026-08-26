using System.Text.Json;

using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Encryption;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Persistence
{
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

            var expected = Path.Join(temp.Path, $"adobe_{accountId}.json");
            Assert.True(File.Exists(expected), $"expected credential file at {expected}");
        }

        [Fact]
        public async Task AddCredentialAsync_LowercasesProviderPrefixInFilename()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var accountId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            var upperPath = Path.Join(temp.Path, $"Adobe_{accountId}.json");
            var lowerPath = Path.Join(temp.Path, $"adobe_{accountId}.json");
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
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);
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
            var filePath = Path.Join(temp.Path, $"adobe_{accountId}.json");
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
            var unrelated = await manager.AddCredentialAsync("Airtable", "main", "Production", "{}");
            Assert.True(await manager.SelectCredentialAsync(accountId));
            Assert.True(await manager.SelectCredentialAsync(unrelated));

            _ = await manager.DeleteCredentialAsync(accountId);

            // Asserted on the selection record itself, not through
            // GetSelectedCredentialAsync. That returns null once the credential file is
            // gone whether or not the selection was cleared, so the previous assertion
            // passed even with the whole clearing block deleted (#50). The record is the
            // only thing that actually distinguishes the two.
            var selectionFile = Path.Join(temp.Path, "selections.json");
            var selections = JsonSerializer.Deserialize<Dictionary<string, string>>(
                await File.ReadAllTextAsync(selectionFile, TestContext.Current.CancellationToken))!;

            Assert.False(selections.ContainsKey("Adobe"));

            // And the delete must not disturb an unrelated provider's selection.
            Assert.True(selections.TryGetValue("Airtable", out var untouched));
            Assert.Equal(unrelated, untouched);

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

            var filePath = Path.Join(temp.Path, $"adobe_{accountId}.json");
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

            var credential = Assert.Single(list);
            var field = Assert.Single(credential.DisplayFields);
            Assert.Equal("Fingerprint", field.Key);
            Assert.Equal("abcd1234", field.Value);
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

            var credential = Assert.Single(list);
            Assert.Equal(accountId, credential.AccountId);
            Assert.True(credential.IsSelected);
            Assert.Equal("{\"key\":\"v\"}", await second.GetSelectedCredentialAsync("Adobe"));
        }

        [Theory]
        [InlineData("not-a-guid")]
        [InlineData("../etc/passwd")]
        [InlineData("*")]
        [InlineData("abc")]
        public async Task DeleteCredentialAsync_NonGuidId_ReturnsFalseWithoutThrowing(string accountId)
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);
            _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            // Malformed ids must not flow into Path.Join / Directory.GetFiles
            // glob — they should resolve to a clean "not found".
            var result = await manager.DeleteCredentialAsync(accountId);

            Assert.False(result);
        }

        [Theory]
        [InlineData("not-a-guid")]
        [InlineData("../etc/passwd")]
        [InlineData("*")]
        public async Task SelectCredentialAsync_NonGuidId_ReturnsFalseWithoutThrowing(string accountId)
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);
            _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            var result = await manager.SelectCredentialAsync(accountId);

            Assert.False(result);
        }

        [Fact]
        public async Task GetCredentialByIdAsync_NonGuidId_Throws()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            await Assert.ThrowsAsync<ArgumentException>(
                () => manager.GetCredentialByIdAsync("Adobe", "not-a-guid"));
        }

        [Fact]
        public async Task SelectCredentialAsync_ConcurrentDifferentProviders_BothPersist()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var adobeId = await manager.AddCredentialAsync("Adobe", "a", "Production", "{}");
            var airtableId = await manager.AddCredentialAsync("Airtable", "b", "Production", "{}");

            // Without the selections lock both calls would read the same
            // pre-write snapshot, mutate their own provider's entry, then both
            // save — last writer wins and one update is lost. With the lock
            // both updates must be observable afterwards.
            await Task.WhenAll(
                manager.SelectCredentialAsync(adobeId),
                manager.SelectCredentialAsync(airtableId));

            var adobe = (await manager.ListCredentialsAsync("Adobe")).Single();
            var airtable = (await manager.ListCredentialsAsync("Airtable")).Single();
            Assert.True(adobe.IsSelected);
            Assert.True(airtable.IsSelected);
        }

        [Fact]
        public async Task ExportCredentialsAsync_ReturnsDecryptedPayloadAndSelection()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);
            var adobeId = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"apiKey\":\"secret\"}");
            _ = await manager.AddCredentialAsync("Airtable", "main", "Production", "{\"apiKey\":\"other\"}");
            Assert.True(await manager.SelectCredentialAsync(adobeId));

            var exports = await manager.ExportCredentialsAsync();

            Assert.Equal(2, exports.Count);
            var adobe = exports.Single(c => c.ProviderName == "Adobe");
            Assert.Equal("prod", adobe.AccountName);
            Assert.Equal("Production", adobe.Environment);
            Assert.Equal("{\"apiKey\":\"secret\"}", adobe.CredentialData); // decrypted
            Assert.True(adobe.IsSelected);
            Assert.False(exports.Single(c => c.ProviderName == "Airtable").IsSelected);
        }

        [Fact]
        public async Task RestoreCredentialAsync_PreservesAccountIdCreatedAtAndSelection()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var record = new CredentialExport
            {
                AccountId = Guid.NewGuid().ToString(),
                AccountName = "prod",
                ProviderName = "Adobe",
                Environment = "Production",
                CredentialData = "{\"apiKey\":\"restored\"}",
                CreatedAt = new DateTime(2018, 5, 6, 7, 8, 9, DateTimeKind.Utc),
                IsSelected = true,
            };

            await manager.RestoreCredentialAsync(record);

            var stored = Assert.Single(await manager.ExportCredentialsAsync());
            Assert.Equal(record.AccountId, stored.AccountId);
            Assert.Equal(record.CreatedAt, stored.CreatedAt);
            Assert.True(stored.IsSelected);
            Assert.Equal("{\"apiKey\":\"restored\"}", await manager.GetCredentialByIdAsync("Adobe", record.AccountId));
        }

        [Fact]
        public async Task RestoreCredentialAsync_SameProviderAndId_ReplacesRatherThanDuplicates()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);
            var id = Guid.NewGuid().ToString();

            CredentialExport Record(string payload) => new()
            {
                AccountId = id,
                AccountName = "prod",
                ProviderName = "Adobe",
                Environment = "Production",
                CredentialData = payload,
                CreatedAt = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                IsSelected = false,
            };

            await manager.RestoreCredentialAsync(Record("{\"v\":1}"));
            await manager.RestoreCredentialAsync(Record("{\"v\":2}"));

            var stored = Assert.Single(await manager.ExportCredentialsAsync());
            Assert.Equal("{\"v\":2}", stored.CredentialData);
        }

        [Fact]
        public async Task RestoreCredentialAsync_InvalidAccountId_Throws()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var bad = new CredentialExport
            {
                AccountId = "../not-a-guid",
                AccountName = "prod",
                ProviderName = "Adobe",
                Environment = "Production",
                CredentialData = "{}",
                CreatedAt = DateTime.UtcNow,
                IsSelected = false,
            };

            _ = await Assert.ThrowsAsync<ArgumentException>(() => manager.RestoreCredentialAsync(bad));
        }

        // ---- Undecryptable credentials (#38) --------------------------------
        //
        // A credentials directory copied between machines/users, or a keystore
        // replaced while its credential files survived, leaves files that parse
        // as JSON with intact plaintext metadata but an unopenable payload. The
        // enumeration paths must tolerate that; the targeted fetch paths must not.

        [Fact]
        public async Task ListCredentialsAsync_UndecryptableCredential_StillListsEveryRow()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path, [new FakeAdobeSummaryProvider()]);

            var goodId = await manager.AddCredentialAsync("Adobe", "good", "Production", "{\"apiKey\":\"KEEP\"}");
            var badId = await manager.AddCredentialAsync("Adobe", "bad", "Production", "{\"apiKey\":\"LOST\"}");
            CredentialCorruption.CorruptPayload(temp.Path, "Adobe", badId);

            var listed = (await manager.ListCredentialsAsync("Adobe")).ToList();

            Assert.Equal(2, listed.Count);

            var good = listed.Single(c => c.AccountId == goodId);
            Assert.True(good.IsDecryptable);
            Assert.NotEmpty(good.DisplayFields);

            // The broken row survives: its id has to stay visible, because that is
            // what `accounts delete <id>` needs to clear it.
            var bad = listed.Single(c => c.AccountId == badId);
            Assert.False(bad.IsDecryptable);
            Assert.Empty(bad.DisplayFields);
            Assert.Equal("bad", bad.AccountName);
        }

        [Fact]
        public async Task ListCredentialsAsync_NoSummaryProvider_DoesNotReadPayload()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path); // no summary provider registered

            var badId = await manager.AddCredentialAsync("Adobe", "bad", "Production", "{}");
            CredentialCorruption.CorruptPayload(temp.Path, "Adobe", badId);

            var listed = (await manager.ListCredentialsAsync("Adobe")).ToList();

            // Nothing is decrypted without a summary provider, so the flag stays
            // true even though the payload is in fact unreadable. Pins the
            // documented meaning of IsDecryptable as a display hint, not a promise.
            Assert.True(Assert.Single(listed).IsDecryptable);
        }

        [Fact]
        public async Task ExportCredentialsAsync_UndecryptableCredential_SkipsItAndKeepsTheRest()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var goodId = await manager.AddCredentialAsync("Adobe", "good", "Production", "{\"k\":\"KEEP\"}");
            var badId = await manager.AddCredentialAsync("Adobe", "bad", "Production", "{\"k\":\"LOST\"}");
            CredentialCorruption.CorruptPayload(temp.Path, "Adobe", badId);

            var exported = await manager.ExportCredentialsAsync();

            // Dropped, never emitted with an empty payload: CredentialData flows
            // straight into the archive, so a blank secret would be silent
            // corruption at the next import.
            var only = Assert.Single(exported);
            Assert.Equal(goodId, only.AccountId);
            Assert.Equal("{\"k\":\"KEEP\"}", only.CredentialData);
        }

        [Fact]
        public async Task DeleteCredentialAsync_UndecryptableCredential_RemovesIt()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var badId = await manager.AddCredentialAsync("Adobe", "bad", "Production", "{}");
            CredentialCorruption.CorruptPayload(temp.Path, "Adobe", badId);

            // The repair path: delete works on metadata alone and never decrypts.
            Assert.True(await manager.DeleteCredentialAsync(badId));
            Assert.False(File.Exists(Path.Join(temp.Path, $"adobe_{badId}.json")));
        }

        [Fact]
        public async Task GetSelectedCredentialAsync_UndecryptableCredential_StillThrows()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var badId = await manager.AddCredentialAsync("Adobe", "bad", "Production", "{}");
            Assert.True(await manager.SelectCredentialAsync(badId));
            CredentialCorruption.CorruptPayload(temp.Path, "Adobe", badId);

            // Deliberately NOT tolerant. This is a targeted fetch: the caller asked
            // for one specific credential and it cannot be supplied. Returning null
            // would masquerade as "no credential selected" and hand the consumer a
            // worse diagnosis than the real one. Guards the enumeration/fetch split
            // against a future over-broad catch.
            _ = await Assert.ThrowsAsync<InvalidOperationException>(
                () => manager.GetSelectedCredentialAsync("Adobe"));
        }

        [Fact]
        public async Task GetCredentialByIdAsync_UndecryptableCredential_StillThrows()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var badId = await manager.AddCredentialAsync("Adobe", "bad", "Production", "{}");
            CredentialCorruption.CorruptPayload(temp.Path, "Adobe", badId);

            _ = await Assert.ThrowsAsync<InvalidOperationException>(
                () => manager.GetCredentialByIdAsync("Adobe", badId));
        }

        [Fact]
        public async Task ListCredentialsAsync_SummaryProviderThrows_StillListsTheCredential()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path, [new ThrowingAdobeSummaryProvider()]);

            var goodId = await manager.AddCredentialAsync("Adobe", "keeps-row", "Production", "{}");

            // The projection throws JsonException, which the outer per-file catch used to
            // swallow along with the whole credential — the row vanished from `accounts
            // list`, so the user could not even see the id to delete it (#52).
            var listed = (await manager.ListCredentialsAsync("Adobe")).ToList();

            var only = Assert.Single(listed);
            Assert.Equal(goodId, only.AccountId);
            Assert.Equal("keeps-row", only.AccountName);
            Assert.Empty(only.DisplayFields);
            Assert.False(only.IsDecryptable);
        }

        [Fact]
        public async Task ListCredentialsAsync_SummaryProviderThrows_DoesNotAffectOtherRows()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path, [new ThrowingAdobeSummaryProvider()]);

            _ = await manager.AddCredentialAsync("Adobe", "a", "Production", "{}");
            _ = await manager.AddCredentialAsync("Adobe", "b", "Production", "{}");

            // One bad projection must not take down the provider's whole listing.
            Assert.Equal(2, (await manager.ListCredentialsAsync("Adobe")).Count());
        }

        /// <summary>
        /// Stands in for a consumer whose projection cannot parse a stored payload —
        /// e.g. one written by an older version of that provider package. The README's
        /// own worked example uses System.Text.Json, so JsonException is the realistic
        /// throw here.
        /// </summary>
        private sealed class ThrowingAdobeSummaryProvider : ICredentialSummaryProvider
        {
            public string ProviderName => "Adobe";

            public IReadOnlyList<KeyValuePair<string, string>> GetDisplayFields(string decryptedCredentialJson) =>
                throw new System.Text.Json.JsonException("provider cannot parse this payload shape");
        }

        [Theory]
        [InlineData("Adobe")]
        [InlineData("adobe")]
        [InlineData("ADOBE")]
        public async Task GetSelectedCredentialAsync_IsCaseInsensitive_LikeListCredentials(string spelling)
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            // Stored under the canonical spelling.
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"v\"}");
            Assert.True(await manager.SelectCredentialAsync(id));

            // ListCredentialsAsync has always matched case-insensitively; the selection
            // lookup did not, so it returned null for exactly the credential the listing
            // was reporting as selected (#48).
            var listed = Assert.Single(await manager.ListCredentialsAsync(spelling));
            Assert.True(listed.IsSelected);
            Assert.Equal("{\"k\":\"v\"}", await manager.GetSelectedCredentialAsync(spelling));
        }

        [Fact]
        public async Task LoadSelections_ToleratesCaseDuplicatesInAHandEditedFile()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");
            Assert.True(await manager.SelectCredentialAsync(id));

            // A case-insensitive dictionary throws on duplicate keys, so a hand-edited
            // file holding both spellings must not take the store down.
            var selectionFile = Path.Join(temp.Path, "selections.json");
            await File.WriteAllTextAsync(
                selectionFile,
                $"{{\"Adobe\":\"{id}\",\"adobe\":\"{id}\"}}",
                TestContext.Current.CancellationToken);

            Assert.Equal("{}", await manager.GetSelectedCredentialAsync("Adobe"));
        }

        [Fact]
        public async Task SelectCredentialAsync_ReplacingAnExistingSelection_LeavesExactlyOneSelected()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);

            var prod = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"PROD\"}");
            var sandbox = await manager.AddCredentialAsync("Adobe", "sandbox", "Sandbox", "{\"k\":\"SANDBOX\"}");

            Assert.True(await manager.SelectCredentialAsync(prod));
            Assert.Equal("{\"k\":\"PROD\"}", await manager.GetSelectedCredentialAsync("Adobe"));

            // Switching between a prod and a sandbox credential is the headline use case in
            // the README, and no test ever exercised the replace path -- only first
            // selections and negative cases (#51).
            Assert.True(await manager.SelectCredentialAsync(sandbox));
            Assert.Equal("{\"k\":\"SANDBOX\"}", await manager.GetSelectedCredentialAsync("Adobe"));

            var listed = (await manager.ListCredentialsAsync("Adobe")).ToList();
            Assert.Equal(2, listed.Count);
            Assert.Single(listed, c => c.IsSelected);
            Assert.True(listed.Single(c => c.AccountId == sandbox).IsSelected);
            Assert.False(listed.Single(c => c.AccountId == prod).IsSelected);
        }

        [Fact]
        public async Task Operations_HonourAnAlreadyCancelledToken()
        {
            using var temp = new TempDir();
            var manager = CreateManager(temp.Path);
            var id = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            using var cts = new CancellationTokenSource();
            await cts.CancelAsync();

            // Every member takes a token as of 2.0.0 (#74); a cancelled one must surface as
            // cancellation rather than being silently ignored.
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => manager.ListCredentialsAsync("Adobe", cts.Token));
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => manager.GetCredentialByIdAsync("Adobe", id, cts.Token));
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => manager.ExportCredentialsAsync(cts.Token));
            _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => manager.AddCredentialAsync("Adobe", "x", "Production", "{}", cts.Token));
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

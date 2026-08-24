using NextIteration.SpectreConsole.Auth.Encryption;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Portability;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Portability
{
    public sealed class CredentialPortabilityServiceTests
    {
        private const string Passphrase = "move-me-between-machines";

        private static FileCredentialManager NewManager(string directory) =>
            new(new LocalFileCredentialEncryption(directory), directory);

        private static async Task<CredentialExport> SingleExportAsync(FileCredentialManager manager) =>
            (await manager.ExportCredentialsAsync()).Single();

        [Fact]
        public async Task ExportThenImport_RoundTripsAllFields_IntoFreshStore()
        {
            using var source = new TempDir();
            using var target = new TempDir();

            var sourceManager = NewManager(source.Path);
            var adobeId = await sourceManager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"a\"}");
            _ = await sourceManager.AddCredentialAsync("Adobe", "sandbox", "Sandbox", "{\"k\":\"b\"}");
            _ = await sourceManager.AddCredentialAsync("Airtable", "main", "Production", "{\"k\":\"c\"}");
            Assert.True(await sourceManager.SelectCredentialAsync(adobeId));

            var exportService = new CredentialPortabilityService(sourceManager);
            var export = await exportService.ExportAsync(Passphrase);
            Assert.Equal(3, export.Count);

            var targetManager = NewManager(target.Path);
            var importService = new CredentialPortabilityService(targetManager);
            var result = await importService.ImportAsync(export.Bundle, Passphrase, (_, _) => ConflictResolution.Skip);

            Assert.Equal(3, result.Added);
            Assert.Equal(0, result.Overwritten);
            Assert.Equal(0, result.Skipped);

            var expected = (await sourceManager.ExportCredentialsAsync()).OrderBy(c => c.AccountId).ToList();
            var actual = (await targetManager.ExportCredentialsAsync()).OrderBy(c => c.AccountId).ToList();

            Assert.Equal(expected.Count, actual.Count);
            for (var i = 0; i < expected.Count; i++)
            {
                Assert.Equal(expected[i].AccountId, actual[i].AccountId);
                Assert.Equal(expected[i].AccountName, actual[i].AccountName);
                Assert.Equal(expected[i].ProviderName, actual[i].ProviderName);
                Assert.Equal(expected[i].Environment, actual[i].Environment);
                Assert.Equal(expected[i].CredentialData, actual[i].CredentialData);
                Assert.Equal(expected[i].CreatedAt, actual[i].CreatedAt);
                Assert.Equal(expected[i].IsSelected, actual[i].IsSelected);
            }

            // The selection followed the credential across the import.
            var selected = actual.Single(c => c.IsSelected);
            Assert.Equal("prod", selected.AccountName);
            Assert.Equal("{\"k\":\"a\"}", await targetManager.GetSelectedCredentialAsync("Adobe"));
        }

        [Fact]
        public async Task Import_Skip_IsIdempotent()
        {
            using var source = new TempDir();
            using var target = new TempDir();

            var sourceManager = NewManager(source.Path);
            _ = await sourceManager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"a\"}");
            var bundle = (await new CredentialPortabilityService(sourceManager).ExportAsync(Passphrase)).Bundle;

            var targetManager = NewManager(target.Path);
            var importService = new CredentialPortabilityService(targetManager);

            var first = await importService.ImportAsync(bundle, Passphrase, (_, _) => ConflictResolution.Skip);
            Assert.Equal(1, first.Added);

            var second = await importService.ImportAsync(bundle, Passphrase, (_, _) => ConflictResolution.Skip);
            Assert.Equal(0, second.Added);
            Assert.Equal(1, second.Skipped);

            Assert.Single(await targetManager.ExportCredentialsAsync());
        }

        [Fact]
        public async Task Import_Overwrite_ReplacesMatchingCredential()
        {
            using var target = new TempDir();
            var targetManager = NewManager(target.Path);

            // Pre-existing credential the incoming one will collide with.
            var existingId = await targetManager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"OLD\"}");

            // Craft an incoming archive with the same identity (provider/name/env)
            // but a different account id and payload.
            var incoming = new CredentialExport
            {
                AccountId = Guid.NewGuid().ToString(),
                AccountName = "prod",
                ProviderName = "Adobe",
                Environment = "Production",
                CredentialData = "{\"k\":\"NEW\"}",
                CreatedAt = new DateTime(2019, 3, 4, 5, 6, 7, DateTimeKind.Utc),
                IsSelected = true,
            };
            var bundle = CredentialArchive.Serialize([incoming], Passphrase);

            var conflictSeen = 0;
            var result = await new CredentialPortabilityService(targetManager)
                .ImportAsync(bundle, Passphrase, (inc, existing) =>
                {
                    conflictSeen++;
                    Assert.Equal("prod", inc.AccountName);

                    // The resolver sees the matched existing credential as metadata
                    // only. Conflict resolution never needs its payload, and
                    // decrypting the store to supply one broke import outright
                    // whenever a single credential was unreadable (#38).
                    Assert.Equal(existingId, existing.AccountId);
                    Assert.Equal("prod", existing.AccountName);
                    Assert.Equal("Adobe", existing.ProviderName);
                    Assert.Equal("Production", existing.Environment);
                    Assert.NotEqual(incoming.AccountId, existing.AccountId);
                    return ConflictResolution.Overwrite;
                });

            Assert.Equal(1, conflictSeen);
            Assert.Equal(1, result.Overwritten);
            Assert.Equal(0, result.Added);

            var stored = await SingleExportAsync(targetManager);
            Assert.Equal(incoming.AccountId, stored.AccountId);
            Assert.Equal("{\"k\":\"NEW\"}", stored.CredentialData);
            Assert.True(stored.IsSelected);
        }

        [Fact]
        public async Task Import_AddsWhenNoConflict_WithoutInvokingResolver()
        {
            using var target = new TempDir();
            var targetManager = NewManager(target.Path);
            _ = await targetManager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"a\"}");

            var incoming = new CredentialExport
            {
                AccountId = Guid.NewGuid().ToString(),
                AccountName = "sandbox", // different name → no collision
                ProviderName = "Adobe",
                Environment = "Sandbox",
                CredentialData = "{\"k\":\"b\"}",
                CreatedAt = new DateTime(2022, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                IsSelected = false,
            };
            var bundle = CredentialArchive.Serialize([incoming], Passphrase);

            var result = await new CredentialPortabilityService(targetManager)
                .ImportAsync(bundle, Passphrase, (_, _) => throw new Xunit.Sdk.XunitException("resolver must not run without a conflict"));

            Assert.Equal(1, result.Added);
            Assert.Equal(0, result.Overwritten);
            Assert.Equal(2, (await targetManager.ExportCredentialsAsync()).Count);
        }

        // ---- Undecryptable credentials in the destination store (#38) --------

        [Fact]
        public async Task Import_UndecryptableCredentialInStore_Succeeds()
        {
            using var target = new TempDir();
            var targetManager = NewManager(target.Path);

            // An unrelated credential the local keystore cannot open. Before the
            // fix this aborted the whole import with an integrity-check error,
            // because conflict detection decrypted the entire store.
            var badId = await targetManager.AddCredentialAsync("Airtable", "stale", "Production", "{\"k\":\"LOST\"}");
            CredentialCorruption.CorruptPayload(target.Path, "Airtable", badId);

            var incoming = new CredentialExport
            {
                AccountId = Guid.NewGuid().ToString(),
                AccountName = "prod",
                ProviderName = "Adobe",
                Environment = "Production",
                CredentialData = "{\"k\":\"NEW\"}",
                CreatedAt = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc),
                IsSelected = false,
            };
            var bundle = CredentialArchive.Serialize([incoming], Passphrase);

            var result = await new CredentialPortabilityService(targetManager)
                .ImportAsync(bundle, Passphrase, (_, _) => ConflictResolution.Skip);

            Assert.Equal(1, result.Added);
            Assert.Equal(0, result.Skipped);
            Assert.Equal("{\"k\":\"NEW\"}", await targetManager.GetCredentialByIdAsync("Adobe", incoming.AccountId));
        }

        [Fact]
        public async Task Import_OverwriteOntoUndecryptableCredential_ReplacesIt()
        {
            using var target = new TempDir();
            var targetManager = NewManager(target.Path);

            var badId = await targetManager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"LOST\"}");
            Assert.True(await targetManager.SelectCredentialAsync(badId));
            CredentialCorruption.CorruptPayload(target.Path, "Adobe", badId);

            var incoming = new CredentialExport
            {
                AccountId = Guid.NewGuid().ToString(),
                AccountName = "prod",
                ProviderName = "Adobe",
                Environment = "Production",
                CredentialData = "{\"k\":\"NEW\"}",
                CreatedAt = new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc),
                IsSelected = true,
            };
            var bundle = CredentialArchive.Serialize([incoming], Passphrase);

            // The unreadable entry is matched on plaintext metadata, so it presents
            // as a conflict rather than silently adding a duplicate alongside it.
            // Overwrite is the invocation that actually repairs a broken store.
            var result = await new CredentialPortabilityService(targetManager)
                .ImportAsync(bundle, Passphrase, (_, _) => ConflictResolution.Overwrite);

            Assert.Equal(1, result.Overwritten);
            Assert.Equal(0, result.Added);

            var stored = await SingleExportAsync(targetManager);
            Assert.Equal(incoming.AccountId, stored.AccountId);
            Assert.Equal("{\"k\":\"NEW\"}", stored.CredentialData);
            Assert.True(stored.IsSelected);
            Assert.False(File.Exists(Path.Join(target.Path, $"adobe_{badId}.json")));
        }

        [Fact]
        public async Task Import_SkipOntoUndecryptableCredential_LeavesStoreBroken()
        {
            using var target = new TempDir();
            var targetManager = NewManager(target.Path);

            var badId = await targetManager.AddCredentialAsync("Adobe", "prod", "Production", "{\"k\":\"LOST\"}");
            CredentialCorruption.CorruptPayload(target.Path, "Adobe", badId);

            var incoming = new CredentialExport
            {
                AccountId = Guid.NewGuid().ToString(),
                AccountName = "prod",
                ProviderName = "Adobe",
                Environment = "Production",
                CredentialData = "{\"k\":\"NEW\"}",
                CreatedAt = DateTime.UtcNow,
                IsSelected = false,
            };
            var bundle = CredentialArchive.Serialize([incoming], Passphrase);

            var result = await new CredentialPortabilityService(targetManager)
                .ImportAsync(bundle, Passphrase, (_, _) => ConflictResolution.Skip);

            // Documents the trap: skip is the non-interactive default, and it repairs
            // nothing. `--on-conflict overwrite` is required to fix a broken store.
            Assert.Equal(1, result.Skipped);
            Assert.Equal(0, result.Added);
            Assert.True(File.Exists(Path.Join(target.Path, $"adobe_{badId}.json")));
        }

        [Fact]
        public async Task Export_UndecryptableCredential_IsReportedAsSkipped()
        {
            using var source = new TempDir();
            var manager = NewManager(source.Path);

            _ = await manager.AddCredentialAsync("Adobe", "good", "Production", "{\"k\":\"KEEP\"}");
            var badId = await manager.AddCredentialAsync("Adobe", "bad", "Production", "{\"k\":\"LOST\"}");
            CredentialCorruption.CorruptPayload(source.Path, "Adobe", badId);

            var export = await new CredentialPortabilityService(manager).ExportAsync(Passphrase);

            // A silently short archive is a data-loss trap: the missing secrets look
            // like they were never stored. The count is surfaced so the command warns.
            Assert.Equal(1, export.Count);
            Assert.Equal(1, export.Skipped);

            var restored = CredentialArchive.Deserialize(export.Bundle, Passphrase);
            Assert.Equal("good", Assert.Single(restored).AccountName);
        }
    }
}

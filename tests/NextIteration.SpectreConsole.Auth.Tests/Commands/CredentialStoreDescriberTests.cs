using NextIteration.SpectreConsole.Auth.Commands;
using NextIteration.SpectreConsole.Auth.Encryption;
using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Tests.Infrastructure;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Commands
{
    public sealed class CredentialStoreDescriberTests
    {
        private static string ValueOf(IReadOnlyList<CredentialStoreFact> facts, string label) =>
            Assert.Single(facts, f => f.Label == label).Value;

        [Fact]
        public void Describe_FileBackendDefaultMode_ReportsPathsAndPortableKeyBinding()
        {
            using var temp = new TempDir();
            var manager = new FileCredentialManager(new LocalFileCredentialEncryption(temp.Path), temp.Path);

            var facts = CredentialStoreDescriber.Describe(manager);

            Assert.Equal("Encrypted files", ValueOf(facts, "Backend"));
            Assert.Equal(Path.GetFullPath(temp.Path), ValueOf(facts, "Credentials directory"));
            Assert.StartsWith("AES-256-GCM", ValueOf(facts, "Encryption"), StringComparison.Ordinal);
            var keyBinding = Assert.Single(facts, f => f.Label == "Key binding");
            Assert.StartsWith("None (default; portable", keyBinding.Value, StringComparison.Ordinal);
            Assert.Equal(Path.Join(Path.GetFullPath(temp.Path), "selections.json"), ValueOf(facts, "Selections file"));
        }

        [Fact]
        public async Task Describe_Keystore_ReportsWhetherItExistsYet()
        {
            using var temp = new TempDir();
            var encryption = new LocalFileCredentialEncryption(temp.Path);
            var manager = new FileCredentialManager(encryption, temp.Path);
            var keystore = Path.Join(Path.GetFullPath(temp.Path), ".keystore");

            Assert.Equal(keystore + " (not created yet)", ValueOf(CredentialStoreDescriber.Describe(manager), "Keystore"));

            _ = await manager.AddCredentialAsync("Adobe", "prod", "Production", "{}");

            Assert.Equal(keystore, ValueOf(CredentialStoreDescriber.Describe(manager), "Keystore"));
        }

        [Fact]
        public void Describe_FileBackendWithEntropy_ReportsHardenedWithoutTheValue()
        {
            using var temp = new TempDir();
            var entropy = "per-deployment-secret"u8.ToArray();
            var manager = new FileCredentialManager(new LocalFileCredentialEncryption(temp.Path, entropy), temp.Path);

            var facts = CredentialStoreDescriber.Describe(manager);

            var keyBinding = Assert.Single(facts, f => f.Label == "Key binding");
            Assert.Equal("AdditionalEntropy (hardened)", keyBinding.Value);
            Assert.Null(keyBinding.Warning);
            Assert.DoesNotContain(facts, f => $"{f.Value} {f.Warning}".Contains("per-deployment-secret", StringComparison.Ordinal));
        }

        [Fact]
        public void Describe_CustomEncryption_NamesTheTypeActuallyInUse()
        {
            using var temp = new TempDir();
            var manager = new FileCredentialManager(new FakeEncryption(), temp.Path);

            var facts = CredentialStoreDescriber.Describe(manager);

            Assert.Equal($"Custom ({typeof(FakeEncryption).FullName})", ValueOf(facts, "Encryption"));
            Assert.DoesNotContain(facts, f => f.Label is "Keystore" or "Key binding");
        }

        [Fact]
        public void Describe_CustomManager_NamesTheTypeAndStillReportsVersionAndPlatform()
        {
            var facts = CredentialStoreDescriber.Describe(new FakeManager());

            Assert.Equal($"Custom ({typeof(FakeManager).FullName})", ValueOf(facts, "Backend"));
            Assert.DoesNotContain("+", ValueOf(facts, "Library version"), StringComparison.Ordinal);
            Assert.NotEmpty(ValueOf(facts, "Platform"));
        }

        [Fact]
        public void DescribeDirectoryPermissions_OwnerOnlyDirectory_IsNotAWarning()
        {
            using var temp = new TempDir();
            var directory = Path.Join(temp.Path, "creds");
            _ = new FileCredentialManager(new FakeEncryption(), directory); // creates it hardened

            var fact = CredentialStoreDescriber.DescribeDirectoryPermissions(directory);

            Assert.Null(fact.Warning);
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal("0700 (owner only)", fact.Value);
            }
        }

        [Fact]
        public void DescribeDirectoryPermissions_GroupReadableDirectory_IsAWarning()
        {
            if (OperatingSystem.IsWindows())
            {
                return; // Unix mode bits; the Windows ACL path is covered by the owner-only test.
            }

            using var temp = new TempDir();
            File.SetUnixFileMode(temp.Path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute);

            var fact = CredentialStoreDescriber.DescribeDirectoryPermissions(temp.Path);

            Assert.Equal("0750", fact.Value);
            Assert.NotNull(fact.Warning);
        }

        [Fact]
        public void DescribeDirectoryPermissions_MissingDirectory_ReportsUnknownWithoutThrowing()
        {
            using var temp = new TempDir();

            var fact = CredentialStoreDescriber.DescribeDirectoryPermissions(Path.Join(temp.Path, "absent"));

            Assert.Equal("Unknown", fact.Value);
            Assert.NotNull(fact.Warning);
        }

        private sealed class FakeEncryption : ICredentialEncryption
        {
            public Task<string> EncryptAsync(string plainText) => Task.FromResult(plainText);

            public Task<string> DecryptAsync(string encryptedText) => Task.FromResult(encryptedText);
        }

        private sealed class FakeManager : ICredentialManager
        {
            public Task<IEnumerable<CredentialSummary>> ListCredentialsAsync(string providerName, CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task<string> AddCredentialAsync(string providerName, string accountName, string environment, string credentialData, CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task<bool> DeleteCredentialAsync(string accountId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task<bool> SelectCredentialAsync(string accountId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task<string?> GetSelectedCredentialAsync(string providerName, CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task<string?> GetCredentialByIdAsync(string providerName, string accountId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task<IEnumerable<string>> GetProviderNamesAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task<IReadOnlyList<CredentialExport>> ExportCredentialsAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
            public Task RestoreCredentialAsync(CredentialExport credential, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        }
    }
}

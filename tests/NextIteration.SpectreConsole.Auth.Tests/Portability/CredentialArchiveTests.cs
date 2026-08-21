using System.Text.Json.Nodes;

using NextIteration.SpectreConsole.Auth.Persistence;
using NextIteration.SpectreConsole.Auth.Portability;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Portability
{
    public sealed class CredentialArchiveTests
    {
        private const string Passphrase = "correct horse battery staple";

        private static CredentialExport Sample(string accountName, string payload, bool selected = false) => new()
        {
            AccountId = Guid.NewGuid().ToString(),
            AccountName = accountName,
            ProviderName = "Adobe",
            Environment = "Production",
            CredentialData = payload,
            CreatedAt = new DateTime(2021, 6, 7, 8, 9, 10, DateTimeKind.Utc),
            IsSelected = selected,
        };

        [Fact]
        public void Serialize_Deserialize_RoundTripsAllFields()
        {
            var input = new List<CredentialExport>
            {
                Sample("prod", "{\"apiKey\":\"one\"}", selected: true),
                Sample("sandbox", "{\"apiKey\":\"two\"}"),
            };

            var bundle = CredentialArchive.Serialize(input, Passphrase);
            var output = CredentialArchive.Deserialize(bundle, Passphrase);

            Assert.Equal(input.Count, output.Count);
            for (var i = 0; i < input.Count; i++)
            {
                Assert.Equal(input[i].AccountId, output[i].AccountId);
                Assert.Equal(input[i].AccountName, output[i].AccountName);
                Assert.Equal(input[i].ProviderName, output[i].ProviderName);
                Assert.Equal(input[i].Environment, output[i].Environment);
                Assert.Equal(input[i].CredentialData, output[i].CredentialData);
                Assert.Equal(input[i].CreatedAt, output[i].CreatedAt);
                Assert.Equal(input[i].IsSelected, output[i].IsSelected);
            }
        }

        [Fact]
        public void Serialize_Deserialize_EmptySet_RoundTrips()
        {
            var bundle = CredentialArchive.Serialize([], Passphrase);
            var output = CredentialArchive.Deserialize(bundle, Passphrase);
            Assert.Empty(output);
        }

        [Fact]
        public void Deserialize_WrongPassphrase_Throws()
        {
            var bundle = CredentialArchive.Serialize([Sample("prod", "{}")], Passphrase);

            var ex = Assert.Throws<InvalidOperationException>(
                () => CredentialArchive.Deserialize(bundle, "not the passphrase"));
            Assert.Contains("passphrase", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Deserialize_TamperedPayload_Throws()
        {
            var bundle = CredentialArchive.Serialize([Sample("prod", "{\"apiKey\":\"secret\"}")], Passphrase);

            // Flip a byte inside the encrypted payload; AES-GCM's tag check must
            // reject it rather than returning garbage plaintext.
            var node = JsonNode.Parse(bundle)!;
            var payload = Convert.FromBase64String(node["payload"]!.GetValue<string>());
            payload[^1] ^= 0xFF;
            node["payload"] = Convert.ToBase64String(payload);
            var tampered = node.ToJsonString();

            _ = Assert.Throws<InvalidOperationException>(
                () => CredentialArchive.Deserialize(tampered, Passphrase));
        }

        [Fact]
        public void Deserialize_NotAnArchive_Throws()
        {
            var ex = Assert.Throws<InvalidOperationException>(
                () => CredentialArchive.Deserialize("this is not json", Passphrase));
            Assert.Contains("archive", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Deserialize_UnsupportedVersion_Throws()
        {
            var bundle = CredentialArchive.Serialize([Sample("prod", "{}")], Passphrase);
            var node = JsonNode.Parse(bundle)!;
            node["version"] = 999;
            var future = node.ToJsonString();

            var ex = Assert.Throws<InvalidOperationException>(
                () => CredentialArchive.Deserialize(future, Passphrase));
            Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
    }
}

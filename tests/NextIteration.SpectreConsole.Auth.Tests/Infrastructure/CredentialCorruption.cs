using System.Text.Json;
using System.Text.Json.Nodes;

namespace NextIteration.SpectreConsole.Auth.Tests.Infrastructure
{
    /// <summary>
    /// Makes a stored credential undecryptable, reproducing the real-world state
    /// behind issue #38: a credentials directory carried to another machine or
    /// user, or a keystore replaced while its credential files survived. In both
    /// cases the file parses fine as JSON and its metadata is intact — only the
    /// AES-GCM payload fails its authentication tag.
    /// </summary>
    /// <remarks>
    /// Corrupting the ciphertext rather than deleting the keystore is deliberate:
    /// it breaks exactly one credential and leaves its neighbours readable, which
    /// is what the tolerance behaviour has to be proven against. Deleting the
    /// keystore would break every credential at once and prove much less.
    /// </remarks>
    internal static class CredentialCorruption
    {
        /// <summary>
        /// Flips a byte inside the encrypted payload of the credential file for
        /// <paramref name="providerName"/>/<paramref name="accountId"/>, leaving
        /// the JSON structure and all plaintext metadata untouched.
        /// </summary>
        internal static void CorruptPayload(string credentialsDirectory, string providerName, string accountId)
        {
            var path = Path.Join(credentialsDirectory, $"{providerName.ToLowerInvariant()}_{accountId}.json");
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"No stored credential at '{path}'.", path);
            }

            var node = JsonNode.Parse(File.ReadAllText(path))
                ?? throw new InvalidOperationException($"'{path}' did not parse as a JSON object.");

            // The manager writes camelCase, matching its JsonSerializerOptions.
            var encoded = node["credentialData"]?.GetValue<string>()
                ?? throw new InvalidOperationException($"'{path}' has no credentialData field.");

            var bytes = Convert.FromBase64String(encoded);

            // Land the flip in the ciphertext, past the [nonce(12)][tag(16)] header,
            // so the failure is an authentication-tag mismatch on real ciphertext
            // rather than a malformed-header rejection.
            const int headerLength = 12 + 16;
            if (bytes.Length <= headerLength)
            {
                throw new InvalidOperationException(
                    $"Payload in '{path}' is {bytes.Length} bytes — too short to corrupt past its header.");
            }

            bytes[headerLength] ^= 0xFF;
            node["credentialData"] = Convert.ToBase64String(bytes);

            File.WriteAllText(path, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}

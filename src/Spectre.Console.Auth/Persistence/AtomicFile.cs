namespace Spectre.Console.Auth.Persistence
{
    /// <summary>
    /// Crash-safe file writers. Each method writes to a uniquely-named temp
    /// file in the same directory as the final path, sets Unix permissions if
    /// requested (while the file is still at its temp path so perms are in
    /// place before it becomes visible at the final location), then performs
    /// an atomic rename to the final path. <see cref="File.Move(string, string, bool)"/>
    /// is atomic on NTFS and backed by <c>rename(2)</c> on POSIX, so readers
    /// observe either the old content or the new content — never a partial
    /// write, even if the process is killed mid-call.
    /// </summary>
    /// <remarks>
    /// This does not serialise concurrent writers. Two processes each writing
    /// a new version observe "last-rename-wins" semantics; whichever rename
    /// completes second determines the final content. This matches the
    /// expected behaviour for interactive CLI commands.
    /// </remarks>
    internal static class AtomicFile
    {
        internal static async Task WriteAllTextAsync(string path, string contents, UnixFileMode? unixMode = null)
        {
            var tempPath = BuildTempPath(path);
            try
            {
                await File.WriteAllTextAsync(tempPath, contents).ConfigureAwait(false);
                ApplyUnixModeIfRequested(tempPath, unixMode);
                File.Move(tempPath, path, overwrite: true);
            }
            catch
            {
                TryDelete(tempPath);
                throw;
            }
        }

        internal static async Task WriteAllBytesAsync(string path, byte[] bytes, UnixFileMode? unixMode = null)
        {
            var tempPath = BuildTempPath(path);
            try
            {
                await File.WriteAllBytesAsync(tempPath, bytes).ConfigureAwait(false);
                ApplyUnixModeIfRequested(tempPath, unixMode);
                File.Move(tempPath, path, overwrite: true);
            }
            catch
            {
                TryDelete(tempPath);
                throw;
            }
        }

        private static string BuildTempPath(string finalPath) =>
            // Unique per call to avoid collisions between concurrent writers,
            // who would otherwise both want the same `{path}.tmp` name.
            $"{finalPath}.{Guid.NewGuid():N}.tmp";

        private static void ApplyUnixModeIfRequested(string path, UnixFileMode? unixMode)
        {
            if (unixMode is null || OperatingSystem.IsWindows())
                return;

            File.SetUnixFileMode(path, unixMode.Value);
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
                // Best-effort cleanup; leaving a stray .tmp file is harmless
                // since it doesn't match the *_{accountId}.json glob used by
                // lookups.
            }
        }
    }
}

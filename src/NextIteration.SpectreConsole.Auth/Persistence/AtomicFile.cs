namespace NextIteration.SpectreConsole.Auth.Persistence
{
    /// <summary>
    /// Crash-safe file writers. Each method writes to a uniquely-named temp
    /// file in the same directory as the final path, sets Unix permissions if
    /// requested (while the file is still at its temp path so perms are in
    /// place before it becomes visible at the final location), then performs
    /// an atomic replace of the final path, so readers observe either the old
    /// content or the new content — never a partial write, even if the process
    /// is killed mid-call.
    ///
    /// The replace primitive differs by platform. On POSIX,
    /// <see cref="File.Move(string, string, bool)"/> is <c>rename(2)</c>, which
    /// replaces the destination even while another handle holds it open, and
    /// serialises concurrent renames. On Windows the same call is
    /// <c>MoveFileEx</c> with <c>MOVEFILE_REPLACE_EXISTING</c>, which does
    /// <em>not</em> tolerate that: it raises a sharing violation when the
    /// destination is open or when two replacements race. Windows therefore uses
    /// <see cref="File.Replace(string, string, string)"/> (<c>ReplaceFile</c>),
    /// which is built for exactly that case, with a short retry for the window
    /// between testing for the destination and replacing it.
    /// </summary>
    /// <remarks>
    /// This does not serialise concurrent writers. Two processes each writing
    /// a new version observe "last-rename-wins" semantics; whichever rename
    /// completes second determines the final content. This matches the
    /// expected behaviour for interactive CLI commands.
    /// </remarks>
    internal static class AtomicFile
    {
        internal static async Task WriteAllTextAsync(string path, string contents, UnixFileMode? unixMode = null, CancellationToken cancellationToken = default)
        {
            var tempPath = BuildTempPath(path);
            try
            {
                await WriteTempAsync(tempPath, System.Text.Encoding.UTF8.GetBytes(contents), unixMode, cancellationToken).ConfigureAwait(false);
                await ReplaceAtomicallyAsync(tempPath, path).ConfigureAwait(false);
            }
            catch
            {
                TryDelete(tempPath);
                throw;
            }
        }

        /// <summary>
        /// Writes the temp file with its final permissions already in place.
        /// </summary>
        /// <remarks>
        /// The mode is applied by <see cref="FileStreamOptions.UnixCreateMode"/> at creation
        /// rather than chmod'd afterwards. Writing first and fixing permissions second left
        /// the whole payload readable at the umask default for the duration of the write.
        /// Inside the credentials directory that is shielded by its own <c>0700</c>, but
        /// <c>accounts export</c> writes to a path the user chooses — exporting to <c>/tmp</c>
        /// or any shared directory exposed every secret in the store for that window (#54).
        /// </remarks>
        private static async Task WriteTempAsync(string tempPath, byte[] bytes, UnixFileMode? unixMode, CancellationToken cancellationToken)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
            };

            if (unixMode is not null && !OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = unixMode.Value;
            }

            await using var stream = new FileStream(tempPath, options);
            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Writes <paramref name="bytes"/> to <paramref name="path"/> only if nothing is
        /// there yet, and reports whether this call is the one that created it.
        /// </summary>
        /// <returns>
        /// <see langword="true"/> when this call created the file; <see langword="false"/>
        /// when another writer got there first, in which case the caller should read what
        /// that writer left rather than assuming its own content is on disk.
        /// </returns>
        /// <remarks>
        /// Same temp-then-rename shape as <see cref="WriteAllBytesAsync"/>, so the file is
        /// still never observable half-written, but the final step is a non-overwriting
        /// move. On both POSIX and Windows that throws when the destination already
        /// exists, which is exactly the signal needed: the losing racer must not clobber
        /// the winner. Used for the keystore, where an overwrite silently destroys every
        /// credential already encrypted under the replaced key.
        /// </remarks>
        internal static async Task<bool> TryWriteNewAsync(string path, byte[] bytes, UnixFileMode? unixMode = null, CancellationToken cancellationToken = default)
        {
            if (File.Exists(path))
            {
                return false;
            }

            var tempPath = BuildTempPath(path);
            try
            {
                await WriteTempAsync(tempPath, bytes, unixMode, cancellationToken).ConfigureAwait(false);

                // Deliberately not overwrite:true. A racing creator that already landed
                // its keystore must win; we then fall back to reading theirs.
                File.Move(tempPath, path);
                return true;
            }
            catch (IOException)
            {
                // Destination appeared between the check and the move: someone else won.
                TryDelete(tempPath);
                return false;
            }
            catch
            {
                TryDelete(tempPath);
                throw;
            }
        }

        internal static async Task WriteAllBytesAsync(string path, byte[] bytes, UnixFileMode? unixMode = null, CancellationToken cancellationToken = default)
        {
            var tempPath = BuildTempPath(path);
            try
            {
                await WriteTempAsync(tempPath, bytes, unixMode, cancellationToken).ConfigureAwait(false);
                await ReplaceAtomicallyAsync(tempPath, path).ConfigureAwait(false);
            }
            catch
            {
                TryDelete(tempPath);
                throw;
            }
        }

        /// <summary>
        /// Moves <paramref name="tempPath"/> onto <paramref name="path"/>,
        /// replacing it if present. See the type remarks for why Windows cannot
        /// use the POSIX path.
        /// </summary>
        private static async Task ReplaceAtomicallyAsync(string tempPath, string path)
        {
            if (!OperatingSystem.IsWindows())
            {
                File.Move(tempPath, path, overwrite: true);
                return;
            }

            const int maxAttempts = 5;
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        // ReplaceFile semantics: tolerates an open destination and
                        // deletes the source on success. No backup file wanted.
                        File.Replace(tempPath, path, destinationBackupFileName: null);
                    }
                    else
                    {
                        // Destination absent, so a plain move is the whole job.
                        // Deliberately not overwrite:true — if a racing writer
                        // created it in the meantime we want the throw, and the
                        // retry below routes us to File.Replace instead.
                        File.Move(tempPath, path);
                    }

                    return;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException && attempt < maxAttempts)
                {
                    // A concurrent writer is mid-replace, or created the
                    // destination between our File.Exists test and the call.
                    // Both are transient; back off and re-evaluate.
                    await Task.Delay(10 * attempt).ConfigureAwait(false);
                }
            }
        }

        // Unique per call to avoid collisions between concurrent writers, who
        // would otherwise both want the same `{path}.tmp` name.
        private static string BuildTempPath(string finalPath) => $"{finalPath}.{Guid.NewGuid():N}.tmp";

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
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

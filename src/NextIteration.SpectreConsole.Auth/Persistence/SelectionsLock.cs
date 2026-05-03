namespace NextIteration.SpectreConsole.Auth.Persistence
{
    /// <summary>
    /// Cross-process advisory lock backed by a sentinel file inside the
    /// credentials directory. Used to serialise <c>selections.json</c>
    /// read-modify-write sequences across concurrent CLI invocations — atomic
    /// rename alone prevents torn files but not lost updates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Implemented via <see cref="FileShare.None"/> on a sentinel file. On
    /// POSIX this maps to <c>flock(LOCK_EX | LOCK_NB)</c>; on Windows it maps
    /// to the share-deny-all mode of <c>CreateFile</c>. In both cases a
    /// second acquirer sees an <see cref="IOException"/> and we retry with
    /// exponential backoff.
    /// </para>
    /// <para>
    /// <see cref="FileOptions.DeleteOnClose"/> auto-removes the sentinel file
    /// when the holder disposes (or its process is killed and the kernel
    /// closes the FD), so there is no stale-lock recovery code to maintain.
    /// </para>
    /// </remarks>
    internal sealed class SelectionsLock : IDisposable
    {
        // Cumulative backoff ~5.1s. Long enough to ride through a normal
        // peer holding the lock for a single read-modify-write, short enough
        // to surface a deadlocked or stuck peer instead of hanging forever.
        private static readonly int[] _delaysMs = [10, 25, 50, 100, 200, 400, 800, 1500, 2000];

        private readonly FileStream _stream;

        private SelectionsLock(FileStream stream) => _stream = stream;

        internal static async Task<SelectionsLock> AcquireAsync(string lockPath, CancellationToken ct = default)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                Options = FileOptions.DeleteOnClose,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            IOException? last = null;
            foreach (var delay in _delaysMs)
            {
                try
                {
                    return new SelectionsLock(new FileStream(lockPath, options));
                }
                catch (IOException ex)
                {
                    last = ex;
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                }
            }

            try
            {
                return new SelectionsLock(new FileStream(lockPath, options));
            }
            catch (IOException ex)
            {
                throw new IOException(
                    $"Could not acquire selections lock at '{lockPath}' after retrying for ~5s. Another process may be holding it.",
                    last ?? ex);
            }
        }

        public void Dispose() => _stream.Dispose();
    }
}

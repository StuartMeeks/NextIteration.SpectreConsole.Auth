using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NextIteration.SpectreConsole.Auth.Persistence.Libsecret;

/// <summary>
/// P/Invoke surface for libsecret-1 (the Secret Service client) plus the
/// slice of GLib (<c>libglib-2.0</c>) needed to build GHashTables of
/// attributes. Marked Linux-only because libsecret isn't a first-class
/// dependency on macOS or Windows — this backend is gated to Linux hosts
/// where a Secret Service daemon (GNOME Keyring, KWallet's shim, etc.) is
/// running.
/// </summary>
[SupportedOSPlatform("linux")]
internal static partial class LibsecretInterop
{
    private const string Libsecret = "libsecret-1.so.0";
    private const string Libglib = "libglib-2.0.so.0";
    private const string Libgobject = "libgobject-2.0.so.0";

    // =========================
    // GLib — GHashTable
    // =========================

    [LibraryImport(Libglib)]
    internal static partial IntPtr g_hash_table_new(IntPtr hashFunc, IntPtr keyEqualFunc);

    [LibraryImport(Libglib)]
    internal static partial IntPtr g_hash_table_new_full(
        IntPtr hashFunc, IntPtr keyEqualFunc, IntPtr keyDestroyFunc, IntPtr valueDestroyFunc);

    [LibraryImport(Libglib)]
    [return: MarshalAs(UnmanagedType.I4)]
    internal static partial int g_hash_table_insert(IntPtr hashTable, IntPtr key, IntPtr value);

    [LibraryImport(Libglib)]
    internal static partial void g_hash_table_unref(IntPtr hashTable);

    [LibraryImport(Libglib)]
    internal static partial IntPtr g_hash_table_lookup(IntPtr hashTable, IntPtr key);

    [LibraryImport(Libglib)]
    internal static partial uint g_hash_table_size(IntPtr hashTable);

    // GLib string utilities for converting managed strings into GLib-managed
    // C strings (since g_hash_table will own the memory of its keys/values
    // when we use a destroy function, we need strings allocated by g_malloc
    // so g_free can release them).

    [LibraryImport(Libglib, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr g_strdup(string str);

    [LibraryImport(Libglib)]
    internal static partial void g_free(IntPtr mem);

    // =========================
    // GLib — GList (result of secret_service_search_sync)
    // =========================

    [LibraryImport(Libglib)]
    internal static partial uint g_list_length(IntPtr list);

    [LibraryImport(Libglib)]
    internal static partial IntPtr g_list_nth_data(IntPtr list, uint n);

    [LibraryImport(Libglib)]
    internal static partial void g_list_free(IntPtr list);

    // =========================
    // GLib — GError
    // =========================

    [StructLayout(LayoutKind.Sequential)]
    internal struct GError
    {
        public uint Domain;
        public int Code;
        public IntPtr Message; // UTF-8 C string owned by GError.
    }

    [LibraryImport(Libglib)]
    internal static partial void g_error_free(IntPtr error);

    // =========================
    // GObject — reference counting
    // =========================

    [LibraryImport(Libgobject)]
    internal static partial void g_object_unref(IntPtr obj);

    // =========================
    // libsecret
    // =========================

    // Search flags — bitfield. 1 = all matches, 2 = unlock automatically, 4 = include secrets in results.
    internal const int SecretSearchAll = 1 << 1;   // SECRET_SEARCH_ALL
    internal const int SecretSearchUnlock = 1 << 2;   // SECRET_SEARCH_UNLOCK
    internal const int SecretSearchLoadSecrets = 1 << 3;   // SECRET_SEARCH_LOAD_SECRETS

    // Collection selector — magic strings as macros in the C headers; the
    // default-collection alias resolves to "default".
    internal const string SecretCollectionDefault = "default";
    internal const string SecretCollectionSession = "session";

    // Schema flag: SECRET_SCHEMA_NONE (0) — no attribute type checking.
    internal const int SecretSchemaNone = 0;

    // secret_schema_new(name, flags, attr_name, attr_type, …, NULL) — varargs.
    // We use the symbol-constant-with-a-custom-schema approach rather than
    // varargs: pass a schema that accepts any string attributes.
    //
    // The simpler path is to pass a schema with a single well-known layout
    // OR pass NULL schema and let libsecret default to SECRET_SCHEMA_COMPAT.
    // Since we need precise control over our attribute names (our own
    // namespace keys, not libsecret's defaults), we build a schema at startup.

    // For simplicity, we use the functions that accept a GHashTable of
    // attributes and a nullable SecretSchema pointer. Passing IntPtr.Zero
    // for the schema makes libsecret treat attributes opaquely.

    [LibraryImport(Libsecret, StringMarshalling = StringMarshalling.Utf8)]
    [return: MarshalAs(UnmanagedType.I4)]
    internal static partial int secret_password_storev_sync(
        IntPtr schema,          // SecretSchema* — IntPtr.Zero means "no schema"
        IntPtr attributes,      // GHashTable* of string → string
        string? collection,     // collection alias or NULL
        string label,
        string password,
        IntPtr cancellable,     // GCancellable* — IntPtr.Zero
        out IntPtr error);

    [LibraryImport(Libsecret, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr secret_password_lookupv_sync(
        IntPtr schema,
        IntPtr attributes,
        IntPtr cancellable,
        out IntPtr error);

    // Free a password string returned by secret_password_lookupv_sync — not
    // g_free, because libsecret may have placed it in non-pageable memory.
    [LibraryImport(Libsecret)]
    internal static partial void secret_password_free(IntPtr password);

    [LibraryImport(Libsecret)]
    [return: MarshalAs(UnmanagedType.I4)]
    internal static partial int secret_password_clearv_sync(
        IntPtr schema,
        IntPtr attributes,
        IntPtr cancellable,
        out IntPtr error);

    // secret_password_searchv_sync returns GList<SecretRetrievable*>. Each
    // retrievable exposes attributes + secret via:
    [LibraryImport(Libsecret)]
    internal static partial IntPtr secret_password_searchv_sync(
        IntPtr schema,
        IntPtr attributes,
        int flags,             // SECRET_SEARCH_* bitmask
        IntPtr cancellable,
        out IntPtr error);

    // SecretRetrievable (actually SecretItem when loaded with ALL flag) —
    // accessors.
    [LibraryImport(Libsecret)]
    internal static partial IntPtr secret_retrievable_get_attributes(IntPtr retrievable);

    [LibraryImport(Libsecret)]
    internal static partial IntPtr secret_retrievable_retrieve_secret_sync(
        IntPtr retrievable,
        IntPtr cancellable,
        out IntPtr error);

    [LibraryImport(Libsecret)]
    internal static partial IntPtr secret_value_get(IntPtr value, out UIntPtr length);

    [LibraryImport(Libsecret)]
    internal static partial void secret_value_unref(IntPtr value);

    [LibraryImport(Libsecret, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr secret_retrievable_get_label(IntPtr retrievable);

    // =========================
    // Helpers — managed over the raw P/Invoke
    // =========================

    /// <summary>
    /// Builds a GHashTable&lt;string,string&gt; from the supplied pairs.
    /// Strings are duplicated into GLib-allocated memory so the destroy
    /// functions (g_free) can release them correctly.
    /// </summary>
    internal static IntPtr NewAttributes(IReadOnlyDictionary<string, string> pairs)
    {
        // Hash/equal funcs for string keys.
        var hashFunc = ResolveExport(Libglib, "g_str_hash");
        var equalFunc = ResolveExport(Libglib, "g_str_equal");
        var freeFunc = ResolveExport(Libglib, "g_free");

        var table = g_hash_table_new_full(hashFunc, equalFunc, freeFunc, freeFunc);
        if (table == IntPtr.Zero)
            throw new InvalidOperationException("g_hash_table_new_full failed.");

        foreach (var (k, v) in pairs)
        {
            var keyPtr = g_strdup(k);
            var valPtr = g_strdup(v);
            _ = g_hash_table_insert(table, keyPtr, valPtr);
        }
        return table;
    }

    /// <summary>
    /// Reads a UTF-8 null-terminated C string at the given pointer without
    /// taking ownership. Returns null for IntPtr.Zero.
    /// </summary>
    internal static string? ReadUtf8(IntPtr ptr) => ptr == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(ptr);

    /// <summary>
    /// Reads the attributes GHashTable from a SecretRetrievable into a
    /// managed dictionary. The returned table is owned by libsecret; we
    /// must call <c>g_hash_table_unref</c> when done.
    /// </summary>
    internal static Dictionary<string, string> ReadAttributes(IntPtr hashTable)
    {
        if (hashTable == IntPtr.Zero) return [];

        // GLib provides g_hash_table_iter_init / g_hash_table_iter_next but
        // the simpler path for our needs is to iterate known keys. Callers
        // pass a list of attribute names they expect and we look them up.
        // For generic enumeration we'd bind the iterator funcs — worth it
        // since our list operation needs to read all attributes.
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var size = g_hash_table_size(hashTable);
        if (size == 0) return result;

        // Bind iter API lazily.
        var iterInit = ResolveExport(Libglib, "g_hash_table_iter_init");
        var iterNext = ResolveExport(Libglib, "g_hash_table_iter_next");

        // GHashTableIter is an opaque struct; callers stack-allocate it.
        // sizeof(GHashTableIter) is 4 gpointers + 1 gint (~40 bytes on
        // 64-bit). We allocate generously to be safe across glib versions.
        var iterBuffer = Marshal.AllocHGlobal(128);
        try
        {
            var initDelegate = Marshal.GetDelegateForFunctionPointer<GHashTableIterInit>(iterInit);
            initDelegate(iterBuffer, hashTable);

            var nextDelegate = Marshal.GetDelegateForFunctionPointer<GHashTableIterNext>(iterNext);
            while (true)
            {
                if (!nextDelegate(iterBuffer, out var keyPtr, out var valPtr)) break;
                var key = ReadUtf8(keyPtr);
                var val = ReadUtf8(valPtr);
                if (key is not null && val is not null)
                {
                    result[key] = val;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(iterBuffer);
        }
        return result;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void GHashTableIterInit(IntPtr iter, IntPtr hashTable);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool GHashTableIterNext(IntPtr iter, out IntPtr key, out IntPtr value);

    /// <summary>
    /// Reads a SecretValue into a managed byte array. Assumes UTF-8 text
    /// (our credential payloads are JSON).
    /// </summary>
    internal static string ReadSecretValueAsString(IntPtr secretValue)
    {
        if (secretValue == IntPtr.Zero) return string.Empty;
        var ptr = secret_value_get(secretValue, out var length);
        if (ptr == IntPtr.Zero) return string.Empty;
        var bytes = new byte[(int)length];
        Marshal.Copy(ptr, bytes, 0, bytes.Length);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> if <paramref name="error"/>
    /// is non-zero, reading the message and freeing the GError before
    /// returning control. The message is copied into the exception, so the
    /// caller retains no pointer into the freed memory.
    /// </summary>
    internal static void ThrowIfGError(IntPtr error, string operation)
    {
        if (error == IntPtr.Zero) return;
        var errStruct = Marshal.PtrToStructure<GError>(error);
        var message = ReadUtf8(errStruct.Message) ?? "(no message)";
        g_error_free(error);
        throw new InvalidOperationException($"{operation} failed: {message}");
    }

    // =========================
    // Dynamic symbol resolution — caches library handles for the duration
    // of the process. GLib's function-pointer constants aren't plain
    // CFString/kSec-style data symbols; they're function addresses, which
    // we need to pass as IntPtr to g_hash_table_new_full.
    // =========================

    private static readonly Dictionary<string, IntPtr> _libraryHandles = [];
    private static readonly Dictionary<string, IntPtr> _symbolCache = [];
    private static readonly Lock _resolveLock = new();

    private static IntPtr ResolveExport(string library, string symbolName)
    {
        lock (_resolveLock)
        {
            var cacheKey = $"{library}!{symbolName}";
            if (_symbolCache.TryGetValue(cacheKey, out var cached)) return cached;

            if (!_libraryHandles.TryGetValue(library, out var handle))
            {
                handle = NativeLibrary.Load(library);
                _libraryHandles[library] = handle;
            }

            var addr = NativeLibrary.GetExport(handle, symbolName);
            _symbolCache[cacheKey] = addr;
            return addr;
        }
    }
}

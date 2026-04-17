using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace NextIteration.SpectreConsole.Auth.Persistence.Keychain;

/// <summary>
/// P/Invoke surface for Apple Security.framework and CoreFoundation.
/// Only the subset needed to implement generic-password keychain items is
/// declared here. All methods are macOS-only and will fail at runtime on
/// other platforms — callers must gate usage behind
/// <see cref="OperatingSystem.IsMacOS"/>.
/// </summary>
[SupportedOSPlatform("macos")]
internal static partial class KeychainInterop
{
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const string Security = "/System/Library/Frameworks/Security.framework/Security";

    // CFString encoding — kCFStringEncodingUTF8.
    internal const uint CFStringEncodingUtf8 = 0x08000100;

    // CFNumberType — kCFNumberSInt32Type / kCFNumberSInt64Type.
    internal const int CFNumberSInt32Type = 3;

    // OSStatus codes we handle explicitly.
    internal const int ErrSecSuccess = 0;
    internal const int ErrSecItemNotFound = -25300;
    internal const int ErrSecDuplicateItem = -25299;
    internal const int ErrSecUserCanceled = -128;

    // =========================
    // CoreFoundation — memory
    // =========================

    [LibraryImport(CoreFoundation)]
    internal static partial void CFRelease(IntPtr cf);

    // =========================
    // CoreFoundation — CFString
    // =========================

    [LibraryImport(CoreFoundation, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr CFStringCreateWithCString(IntPtr allocator, string cStr, uint encoding);

    [LibraryImport(CoreFoundation)]
    internal static partial long CFStringGetLength(IntPtr theString);

    [LibraryImport(CoreFoundation)]
    internal static partial long CFStringGetMaximumSizeForEncoding(long length, uint encoding);

    [LibraryImport(CoreFoundation)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool CFStringGetCString(IntPtr theString, IntPtr buffer, long bufferSize, uint encoding);

    // =========================
    // CoreFoundation — CFData
    // =========================

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFDataCreate(IntPtr allocator, IntPtr bytes, long length);

    [LibraryImport(CoreFoundation)]
    internal static partial long CFDataGetLength(IntPtr theData);

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFDataGetBytePtr(IntPtr theData);

    // =========================
    // CoreFoundation — CFDictionary
    // =========================

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFDictionaryCreateMutable(
        IntPtr allocator, long capacity, IntPtr keyCallBacks, IntPtr valueCallBacks);

    [LibraryImport(CoreFoundation)]
    internal static partial void CFDictionarySetValue(IntPtr theDict, IntPtr key, IntPtr value);

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFDictionaryGetValue(IntPtr theDict, IntPtr key);

    // =========================
    // CoreFoundation — CFArray
    // =========================

    [LibraryImport(CoreFoundation)]
    internal static partial long CFArrayGetCount(IntPtr theArray);

    [LibraryImport(CoreFoundation)]
    internal static partial IntPtr CFArrayGetValueAtIndex(IntPtr theArray, long idx);

    // =========================
    // CoreFoundation — CFType introspection
    //
    // Used to distinguish CFArray vs CFDictionary results from
    // SecItemCopyMatching. Probing a CFArray with CFDictionaryGetValue
    // toll-free-bridges to [NSArray objectForKey:] which doesn't exist and
    // raises NSInvalidArgumentException — crashing the process. Checking the
    // CF type ID first is the supported way.
    // =========================

    [LibraryImport(CoreFoundation)]
    internal static partial UIntPtr CFGetTypeID(IntPtr cf);

    [LibraryImport(CoreFoundation)]
    internal static partial UIntPtr CFArrayGetTypeID();

    [LibraryImport(CoreFoundation)]
    internal static partial UIntPtr CFDictionaryGetTypeID();

    // =========================
    // CoreFoundation — CFDate / CFNumber
    // =========================

    [LibraryImport(CoreFoundation)]
    internal static partial double CFDateGetAbsoluteTime(IntPtr theDate);

    [LibraryImport(CoreFoundation)]
    [return: MarshalAs(UnmanagedType.U1)]
    internal static partial bool CFNumberGetValue(IntPtr number, long theType, out int value);

    // =========================
    // Security.framework
    // =========================

    [LibraryImport(Security)]
    internal static partial int SecItemAdd(IntPtr query, out IntPtr result);

    [LibraryImport(Security)]
    internal static partial int SecItemCopyMatching(IntPtr query, out IntPtr result);

    [LibraryImport(Security)]
    internal static partial int SecItemUpdate(IntPtr query, IntPtr attributesToUpdate);

    [LibraryImport(Security)]
    internal static partial int SecItemDelete(IntPtr query);

    // =========================
    // kSec* / kCF* data constants — loaded once via dlopen/dlsym at first use.
    // These are CFString/CFBoolean globals exported from the frameworks. The
    // symbol yields a pointer TO a CFTypeRef, so we read one IntPtr from it.
    // =========================

    internal static class Constants
    {
        // Security.framework item-class keys.
        internal static readonly IntPtr KSecClass = LoadSymbol(Security, "kSecClass");
        internal static readonly IntPtr KSecClassGenericPassword = LoadSymbol(Security, "kSecClassGenericPassword");

        // Attribute keys we write on each item.
        internal static readonly IntPtr KSecAttrService = LoadSymbol(Security, "kSecAttrService");
        internal static readonly IntPtr KSecAttrAccount = LoadSymbol(Security, "kSecAttrAccount");
        internal static readonly IntPtr KSecAttrLabel = LoadSymbol(Security, "kSecAttrLabel");
        internal static readonly IntPtr KSecAttrDescription = LoadSymbol(Security, "kSecAttrDescription");
        internal static readonly IntPtr KSecAttrGeneric = LoadSymbol(Security, "kSecAttrGeneric");
        internal static readonly IntPtr KSecAttrCreationDate = LoadSymbol(Security, "kSecAttrCreationDate");
        internal static readonly IntPtr KSecValueData = LoadSymbol(Security, "kSecValueData");

        // Query modifiers.
        internal static readonly IntPtr KSecMatchLimit = LoadSymbol(Security, "kSecMatchLimit");
        internal static readonly IntPtr KSecMatchLimitAll = LoadSymbol(Security, "kSecMatchLimitAll");
        internal static readonly IntPtr KSecMatchLimitOne = LoadSymbol(Security, "kSecMatchLimitOne");
        internal static readonly IntPtr KSecReturnAttributes = LoadSymbol(Security, "kSecReturnAttributes");
        internal static readonly IntPtr KSecReturnData = LoadSymbol(Security, "kSecReturnData");

        // CoreFoundation boolean singletons.
        internal static readonly IntPtr KCFBooleanTrue = LoadSymbol(CoreFoundation, "kCFBooleanTrue");

        private static IntPtr LoadSymbol(string library, string symbolName)
        {
            var libHandle = NativeLibrary.Load(library);
            // The symbol is a pointer TO a CFTypeRef — dereference one IntPtr.
            var address = NativeLibrary.GetExport(libHandle, symbolName);
            return Marshal.ReadIntPtr(address);
        }
    }

    // =========================
    // Managed helpers over the raw P/Invoke — each takes ownership of the
    // returned CF handle and must be released by the caller.
    // =========================

    /// <summary>
    /// Creates a CFString from a UTF-8 .NET string. Caller must
    /// <see cref="CFRelease"/> the returned handle.
    /// </summary>
    internal static IntPtr NewCfString(string value)
    {
        var handle = CFStringCreateWithCString(IntPtr.Zero, value, CFStringEncodingUtf8);
        if (handle == IntPtr.Zero)
            throw new InvalidOperationException($"CFStringCreateWithCString failed for '{value}'.");
        return handle;
    }

    /// <summary>
    /// Creates a CFData from a byte array. Caller must
    /// <see cref="CFRelease"/> the returned handle.
    /// </summary>
    internal static IntPtr NewCfData(ReadOnlySpan<byte> bytes)
    {
        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                var handle = CFDataCreate(IntPtr.Zero, (IntPtr)ptr, bytes.Length);
                if (handle == IntPtr.Zero)
                    throw new InvalidOperationException("CFDataCreate failed.");
                return handle;
            }
        }
    }

    /// <summary>
    /// Reads a CFString back into a managed string (UTF-8).
    /// </summary>
    internal static string ReadCfString(IntPtr cfString)
    {
        if (cfString == IntPtr.Zero) return string.Empty;

        var length = CFStringGetLength(cfString);
        var maxBytes = CFStringGetMaximumSizeForEncoding(length, CFStringEncodingUtf8) + 1;

        var buffer = Marshal.AllocHGlobal(checked((IntPtr)maxBytes));
        try
        {
            if (!CFStringGetCString(cfString, buffer, maxBytes, CFStringEncodingUtf8))
                throw new InvalidOperationException("CFStringGetCString failed.");
            return Marshal.PtrToStringUTF8(buffer) ?? string.Empty;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Reads a CFData back into a managed byte array.
    /// </summary>
    internal static byte[] ReadCfData(IntPtr cfData)
    {
        if (cfData == IntPtr.Zero) return [];

        var length = (int)CFDataGetLength(cfData);
        if (length == 0) return [];

        var bytesPtr = CFDataGetBytePtr(cfData);
        var managed = new byte[length];
        Marshal.Copy(bytesPtr, managed, 0, length);
        return managed;
    }

    /// <summary>
    /// Reads a CFDate as UTC <see cref="DateTime"/>. CF absolute time is
    /// seconds since 2001-01-01T00:00:00Z.
    /// </summary>
    internal static DateTime ReadCfDate(IntPtr cfDate)
    {
        var cfEpoch = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var seconds = CFDateGetAbsoluteTime(cfDate);
        return cfEpoch.AddSeconds(seconds);
    }

    /// <summary>
    /// Builds a mutable CFDictionary out of the supplied key/value pairs.
    /// Caller must <see cref="CFRelease"/> the returned handle.
    /// </summary>
    internal static IntPtr NewCfDictionary(IReadOnlyList<(IntPtr Key, IntPtr Value)> pairs)
    {
        // kCFTypeDictionaryKeyCallBacks / kCFTypeDictionaryValueCallBacks
        // are the standard callbacks that retain/release CF types. We pass
        // IntPtr.Zero which makes the dictionary bag-of-pointers — fine for
        // our usage because all values we pass in remain alive for the
        // duration of the call.
        var dict = CFDictionaryCreateMutable(IntPtr.Zero, pairs.Count, IntPtr.Zero, IntPtr.Zero);
        if (dict == IntPtr.Zero)
            throw new InvalidOperationException("CFDictionaryCreateMutable failed.");

        foreach (var (key, value) in pairs)
        {
            // Skip pairs with a NULL value — callers use IntPtr.Zero as a
            // "don't include this key at all" marker (e.g. conditional
            // kSecReturnData). Sending a NULL-valued entry to
            // Security.framework causes errSecParam on some queries.
            if (value == IntPtr.Zero) continue;
            CFDictionarySetValue(dict, key, value);
        }
        return dict;
    }
}

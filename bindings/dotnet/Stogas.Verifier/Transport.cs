using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Stogas.Verifier;

public sealed record TransportOptions
{
    [JsonPropertyName("environment")] public string Environment { get; init; } = "prod";
    [JsonPropertyName("security")] public string Security { get; init; } = "tls";
    [JsonPropertyName("max_connections")] public uint MaxConnections { get; init; } = 4;
    [JsonPropertyName("base_url")] public string? BaseUrl { get; init; }
}

public sealed class VerificationException(string message, string code) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>A managed confidential transport. Use BaseUrl with an HTTP/OpenAI client with retries disabled.</summary>
public sealed class Transport : IDisposable
{
    private readonly TransportHandle handle;
    private readonly object closeLock = new();
    public Uri BaseUrl { get; }

    public Transport(TransportOptions? options = null)
    {
        if (Native.AbiVersion() != 1) throw new NotSupportedException("Unsupported Stogas native ABI.");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(options ?? new TransportOptions());
        nint raw = Native.Start(bytes, (nuint)bytes.Length, out nint pointer);
        handle = new TransportHandle(pointer);
        try
        {
            JsonElement value = Native.Result(raw);
            if (handle.IsInvalid) throw new InvalidOperationException("Native transport returned no handle.");
            BaseUrl = new Uri(value.GetProperty("base_url").GetString()!, UriKind.Absolute);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>Refresh verification evidence without replaying any inference.</summary>
    public bool Refresh() => Native.Result(Native.Refresh(handle)).GetBoolean();

    /// <summary>Close once, allowing the native transport up to five seconds to finish active work.</summary>
    public void Dispose()
    {
        lock (closeLock)
        {
            if (handle.IsClosed) return;
            try { Native.Close(handle); }
            finally { handle.Dispose(); }
        }
    }
}

internal sealed class TransportHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal TransportHandle(nint pointer) : base(true) => SetHandle(pointer);
    protected override bool ReleaseHandle()
    {
        Native.Free(handle);
        return true;
    }
}

internal static partial class Native
{
    private const string Library = "stogas_verifier_ffi";
    [LibraryImport(Library, EntryPoint = "stogas_verifier_abi_version")]
    internal static partial uint AbiVersion();
    [LibraryImport(Library, EntryPoint = "stogas_transport_start")]
    internal static partial nint Start(byte[] configuration, nuint length, out nint handle);
    [LibraryImport(Library, EntryPoint = "stogas_transport_refresh")]
    internal static partial nint Refresh(TransportHandle handle);
    [LibraryImport(Library, EntryPoint = "stogas_transport_close")]
    internal static partial void Close(TransportHandle handle);
    [LibraryImport(Library, EntryPoint = "stogas_transport_free")]
    internal static partial void Free(nint handle);
    [LibraryImport(Library, EntryPoint = "stogas_verifier_string_free")]
    private static partial void FreeString(nint value);

    internal static JsonElement Result(nint pointer)
    {
        if (pointer == 0) throw new InvalidOperationException("Native transport returned no result.");
        try
        {
            using JsonDocument document = JsonDocument.Parse(Marshal.PtrToStringUTF8(pointer)!);
            JsonElement root = document.RootElement;
            if (!root.GetProperty("ok").GetBoolean())
                throw new VerificationException(root.GetProperty("error").GetString()!, root.GetProperty("code").GetString()!);
            return root.GetProperty("value").Clone();
        }
        finally { FreeString(pointer); }
    }
}

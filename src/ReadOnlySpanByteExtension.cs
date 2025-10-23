using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Soenneker.Enums.ContentKinds;

namespace Soenneker.Extensions.Spans.Readonly.Bytes;

/// <summary>
/// A collection of helpful ReadOnlySpan (byte) extension methods
/// </summary>
public static class ReadOnlySpanByteExtension
{
    private static readonly SearchValues<byte> _ws = SearchValues.Create(" \t\r\n"u8);

    /// <summary>Bytes → SHA-256 hex (uppercase by default)</summary>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static string ToSha256Hex(this ReadOnlySpan<byte> data, bool upperCase = true)
    {
        Span<byte> hash = stackalloc byte[32]; // SHA-256 output (uninitialized is fine)
        SHA256.TryHashData(data, hash, out _);
        return upperCase ? Convert.ToHexString(hash) : Convert.ToHexStringLower(hash);
    }

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeJson(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Json;

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeXmlOrHtml(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.XmlOrHtml;

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksBinary(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Binary;

    [Pure, MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static ContentKind Classify(this ReadOnlySpan<byte> utf8)
    {
        // Skip UTF-8 BOM
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
            utf8 = utf8[3..];

        if (utf8.IsEmpty)
            return ContentKind.Unknown;

        // Quick binary heuristic (first 512 bytes)
        int limit = utf8.Length < 512 ? utf8.Length : 512;
        ReadOnlySpan<byte> head = utf8.Slice(0, limit);

        // NUL is a strong binary signal; this is fast (vectorized internally)
        if (head.IndexOf((byte)0) >= 0)
            return ContentKind.Binary;

        // Count C0 controls except \t \n \r
        var controls = 0;

        for (var i = 0; i < head.Length; i++)
        {
            byte b = head[i];
            if (b < 0x20 && b != (byte)'\t' && b != (byte)'\n' && b != (byte)'\r')
                controls++;
        }

        if (controls > limit / 10) // >10% controls => likely binary
            return ContentKind.Binary;

        // Skip RFC 8259 JSON whitespace in one shot
        int idx = utf8.IndexOfAnyExcept(_ws);
        if (idx < 0)
            return ContentKind.Unknown;

        byte c = utf8[idx];

        switch (c)
        {
            // JSON containers
            case (byte)'{' or (byte)'[':
            // JSON top-level primitives
            case (byte)'"':
            case (byte)'-':
            case >= (byte)'0' and <= (byte)'9':
            // true/false/null
            case (byte)'t' or (byte)'f' or (byte)'n':
                return ContentKind.Json;
            case (byte)'<':
                return ContentKind.XmlOrHtml;
            default:
                return ContentKind.Text;
        }
    }
}

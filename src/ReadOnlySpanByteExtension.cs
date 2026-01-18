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

    private const int _probeLimit = 512;

    /// <summary>Bytes → SHA-256 hex (uppercase by default)</summary>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static string ToSha256Hex(this ReadOnlySpan<byte> data, bool upperCase = true)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.TryHashData(data, hash, out _);
        return upperCase ? Convert.ToHexString(hash) : Convert.ToHexStringLower(hash);
    }

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeJson(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Json;

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeXmlOrHtml(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.XmlOrHtml;

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksBinary(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Binary;

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ContainsNonAscii(this ReadOnlySpan<byte> utf8)
        => utf8.IndexOfAnyInRange((byte)0x80, (byte)0xFF) >= 0;

    [Pure]
    public static bool Utf8AsciiEqualsIgnoreCase(this ReadOnlySpan<byte> leftAscii, ReadOnlySpan<byte> rightAscii)
    {
        if (leftAscii.Length != rightAscii.Length)
            return false;

        for (int i = 0; i < leftAscii.Length; i++)
        {
            byte a = leftAscii[i];
            byte b = rightAscii[i];

            if (a == b)
                continue;

            if ((uint)(a - (byte)'A') <= 'Z' - 'A')
                a = (byte)(a + 32);

            if ((uint)(b - (byte)'A') <= 'Z' - 'A')
                b = (byte)(b + 32);

            if (a != b)
                return false;
        }

        return true;
    }

    [Pure, MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static ContentKind Classify(this ReadOnlySpan<byte> utf8)
    {
        // Skip UTF-8 BOM
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
            utf8 = utf8.Slice(3);

        if (utf8.IsEmpty)
            return ContentKind.Unknown;

        int limit = utf8.Length <= _probeLimit ? utf8.Length : _probeLimit;
        ReadOnlySpan<byte> head = utf8.Slice(0, limit);

        // Strong binary signal
        if (head.IndexOf((byte)0) >= 0)
            return ContentKind.Binary;

        // Count C0 controls except \t \n \r
        int controls = 0;
        for (int i = 0; i < head.Length; i++)
        {
            byte b = head[i];
            if (b < 0x20 && b != (byte)'\t' && b != (byte)'\n' && b != (byte)'\r')
                controls++;
        }

        if (controls > (limit / 10))
            return ContentKind.Binary;

        // Find first non-whitespace (bounded to probe window)
        int idx = head.IndexOfAnyExcept(_ws);
        if (idx < 0)
            return utf8.Length == head.Length ? ContentKind.Unknown : ContentKind.Text;

        byte c = head[idx];

        return c switch
        {
            (byte)'{' or (byte)'[' => ContentKind.Json,
            (byte)'"' => ContentKind.Json,
            (byte)'-' => ContentKind.Json,
            >= (byte)'0' and <= (byte)'9' => ContentKind.Json,
            (byte)'t' or (byte)'f' or (byte)'n' => ContentKind.Json,
            (byte)'<' => ContentKind.XmlOrHtml,
            _ => ContentKind.Text
        };
    }
}
using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Soenneker.Enums.ContentKinds;

namespace Soenneker.Extensions.Spans.Readonly.Bytes;

/// <summary>
/// Provides extension methods for analyzing and processing read-only spans of bytes, including hashing, content
/// classification, and ASCII operations.
/// </summary>
/// <remarks>This static class offers utility methods for common byte span scenarios such as computing SHA-256
/// hashes, detecting content types (JSON, XML/HTML, binary), and performing ASCII comparisons. All methods are
/// allocation-free unless otherwise noted and are optimized for performance in high-throughput or streaming
/// contexts.</remarks>
public static class ReadOnlySpanByteExtension
{
    private static readonly SearchValues<byte> _ws = SearchValues.Create(" \t\r\n"u8);

    private const int _probeLimit = 512;

    // 32 bytes hash => 64 hex chars
    private const int _sha256Bytes = 32;
    private const int _sha256HexChars = _sha256Bytes * 2;

    private static ReadOnlySpan<char> _hexUpper => "0123456789ABCDEF";
    private static ReadOnlySpan<char> _hexLower => "0123456789abcdef";

    /// <summary>
    /// Computes the SHA-256 hash of the specified byte span and returns its hexadecimal representation.
    /// </summary>
    /// <remarks>
    /// The resulting string is always 64 characters long (32 bytes × 2 hex characters).
    /// This method allocates only the returned <see cref="string"/>.
    /// For allocation-free scenarios, use <see cref="TryWriteSha256Hex(ReadOnlySpan{byte}, Span{char}, bool, out int)"/>.
    /// </remarks>
    /// <param name="data">The input data to hash.</param>
    /// <param name="upperCase">
    /// If <see langword="true"/>, produces uppercase hexadecimal characters; otherwise, lowercase.
    /// </param>
    /// <returns>
    /// A 64-character hexadecimal string representing the SHA-256 hash of the input.
    /// </returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static string ToSha256Hex(this ReadOnlySpan<byte> data, bool upperCase = true)
    {
        Span<char> chars = stackalloc char[_sha256HexChars];
        TryWriteSha256Hex(data, chars, upperCase, out int written);
        // written should always be 64 here
        return new string(chars.Slice(0, written));
    }

    /// <summary>
    /// Computes the SHA-256 hash of the specified byte span and writes its hexadecimal representation into a destination buffer.
    /// </summary>
    /// <remarks>
    /// This method performs no managed heap allocations.
    /// The destination span must be at least 64 characters in length.
    /// </remarks>
    /// <param name="data">The input data to hash.</param>
    /// <param name="destination">
    /// The destination buffer that receives the hexadecimal characters.
    /// Must be at least 64 characters in length.
    /// </param>
    /// <param name="upperCase">
    /// If <see langword="true"/>, produces uppercase hexadecimal characters; otherwise, lowercase.
    /// </param>
    /// <param name="charsWritten">
    /// When this method returns, contains the number of characters written to <paramref name="destination"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the hash was successfully written to <paramref name="destination"/>; 
    /// otherwise, <see langword="false"/> if the destination buffer was too small or hashing failed.
    /// </returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static bool TryWriteSha256Hex(
        this ReadOnlySpan<byte> data,
        Span<char> destination,
        bool upperCase,
        out int charsWritten)
    {
        if ((uint)destination.Length < _sha256HexChars)
        {
            charsWritten = 0;
            return false;
        }

        Span<byte> hash = stackalloc byte[_sha256Bytes];

        if (!SHA256.TryHashData(data, hash, out int hashWritten) || hashWritten != _sha256Bytes)
        {
            charsWritten = 0;
            return false;
        }

        EncodeHex(hash, destination, upperCase);
        charsWritten = _sha256HexChars;
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static void EncodeHex(ReadOnlySpan<byte> bytes, Span<char> dest, bool upperCase)
    {
        ReadOnlySpan<char> hex = upperCase ? _hexUpper : _hexLower;

        int di = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            dest[di++] = hex[b >> 4];
            dest[di++] = hex[b & 0xF];
        }
    }

    /// <summary>
    /// Determines whether the specified UTF-8 byte span appears to represent JSON content.
    /// </summary>
    /// <remarks>This method performs a lightweight check and does not fully validate the JSON structure. Use
    /// for quick heuristics, not for strict validation.</remarks>
    /// <param name="utf8">A read-only span of bytes containing UTF-8 encoded data to analyze.</param>
    /// <returns>true if the content appears to be JSON; otherwise, false.</returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeJson(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Json;

    /// <summary>
    /// Determines whether the specified UTF-8 byte span appears to contain XML or HTML content.
    /// </summary>
    /// <remarks>
    /// This method performs a heuristic inspection based on leading content and control character density.
    /// It does not validate well-formedness or correctness of markup.
    /// </remarks>
    /// <param name="utf8">
    /// A read-only span of bytes representing UTF-8 encoded data to examine.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the content appears to be XML or HTML; otherwise, <see langword="false"/>.
    /// </returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeXmlOrHtml(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.XmlOrHtml;

    /// <summary>
    /// Determines whether the specified UTF-8 byte span appears to contain binary (non-text) content.
    /// </summary>
    /// <remarks>
    /// Binary classification is based on null-byte detection and excessive control characters
    /// within a bounded probe window.
    /// </remarks>
    /// <param name="utf8">
    /// A read-only span of bytes representing UTF-8 encoded data to examine.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the content appears to be binary; otherwise, <see langword="false"/>.
    /// </returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksBinary(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Binary;

    /// <summary>
    /// Determines whether the specified byte span contains any non-ASCII bytes.
    /// </summary>
    /// <remarks>
    /// ASCII bytes are defined as values in the range 0x00 through 0x7F.
    /// This method does not validate UTF-8 correctness.
    /// </remarks>
    /// <param name="utf8">
    /// A read-only span of bytes to inspect.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if at least one byte is greater than 0x7F; otherwise, <see langword="false"/>.
    /// </returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ContainsNonAscii(this ReadOnlySpan<byte> utf8)
        => utf8.IndexOfAnyInRange((byte)0x80, (byte)0xFF) >= 0;

    /// <summary>
    /// Performs a case-insensitive comparison of two ASCII byte spans.
    /// </summary>
    /// <remarks>
    /// This method assumes both inputs contain ASCII characters only.
    /// Case folding is performed using a fast ASCII-only transformation and does not support
    /// culture-aware or full Unicode case comparison.
    /// </remarks>
    /// <param name="leftAscii">The first ASCII byte span to compare.</param>
    /// <param name="rightAscii">The second ASCII byte span to compare.</param>
    /// <returns>
    /// <see langword="true"/> if the spans are equal using ASCII case-insensitive comparison;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static bool Utf8AsciiEqualsIgnoreCase(this ReadOnlySpan<byte> leftAscii, ReadOnlySpan<byte> rightAscii)
    {
        int len = leftAscii.Length;
        if (len != rightAscii.Length)
            return false;

        for (int i = 0; i < len; i++)
        {
            byte a = leftAscii[i];
            byte b = rightAscii[i];

            if (a == b)
                continue;

            // Fold ASCII to lowercase via | 0x20, then validate it's a letter.
            byte af = (byte)(a | 0x20);
            byte bf = (byte)(b | 0x20);

            // If both are letters and equal after folding -> match; otherwise fail.
            if ((uint)(af - (byte)'a') <= 'z' - 'a' && af == bf)
                continue;

            return false;
        }

        return true;
    }

    /// <summary>
    /// Classifies the specified UTF-8 byte span into a high-level content category.
    /// </summary>
    /// <remarks>
    /// The classification is heuristic-based and examines only a bounded prefix of the input
    /// (up to 512 bytes). The method:
    /// <list type="bullet">
    /// <item><description>Skips a UTF-8 BOM if present.</description></item>
    /// <item><description>Detects strong binary signals such as null bytes.</description></item>
    /// <item><description>Measures control character density to identify binary data.</description></item>
    /// <item><description>Inspects the first non-whitespace byte to infer JSON or XML/HTML.</description></item>
    /// </list>
    /// This method does not validate format correctness.
    /// </remarks>
    /// <param name="utf8">
    /// A read-only span of bytes representing UTF-8 encoded data to classify.
    /// </param>
    /// <returns>
    /// A <see cref="ContentKind"/> value indicating the detected content category.
    /// </returns>
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

        // Count C0 controls except \t \n \r, but bail as soon as it crosses threshold.
        int cutoff = limit / 10 + 1; // strictly ">" 10% => fail; +1 lets us early-exit on crossing
        int controls = 0;

        for (int i = 0; i < head.Length; i++)
        {
            byte b = head[i];

            // C0 control range
            if (b < 0x20 && b != (byte)'\t' && b != (byte)'\n' && b != (byte)'\r')
            {
                if (++controls >= cutoff)
                    return ContentKind.Binary;
            }
        }

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
using System;
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
    private const int _probeLimit = 512;

    // 32 bytes hash => 64 hex chars
    private const int _sha256Bytes = 32;
    private const int _sha256HexChars = 64;

    private const string _hexUpper = "0123456789ABCDEF";
    private const string _hexLower = "0123456789abcdef";

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
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string ToSha256Hex(this ReadOnlySpan<byte> data, bool upperCase = true)
    {
        Span<char> chars = stackalloc char[_sha256HexChars];

        if (!TryWriteSha256Hex(data, chars, upperCase, out _))
            throw new InvalidOperationException("Failed to compute SHA-256 hash.");

        return new string(chars);
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
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryWriteSha256Hex(this ReadOnlySpan<byte> data, Span<char> destination, bool upperCase, out int charsWritten)
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void EncodeHex(ReadOnlySpan<byte> bytes, Span<char> destination, bool upperCase)
    {
        ReadOnlySpan<char> hex = upperCase ? _hexUpper : _hexLower;

        int di = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            destination[di++] = hex[b >> 4];
            destination[di++] = hex[b & 0x0F];
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
    public static bool ContainsNonAscii(this ReadOnlySpan<byte> utf8) => utf8.IndexOfAnyInRange((byte)0x80, (byte)0xFF) >= 0;

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
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Utf8AsciiEqualsIgnoreCase(this ReadOnlySpan<byte> leftAscii, ReadOnlySpan<byte> rightAscii)
    {
        int length = leftAscii.Length;
        if (length != rightAscii.Length)
            return false;

        for (int i = 0; i < length; i++)
        {
            byte a = leftAscii[i];
            byte b = rightAscii[i];

            if (a == b)
                continue;

            byte af = (byte)(a | 0x20);
            if (af != (byte)(b | 0x20) || (uint)(af - (byte)'a') > (byte)('z' - 'a'))
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
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ContentKind Classify(this ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
        {
            utf8 = utf8[3..];
        }

        if (utf8.IsEmpty)
            return ContentKind.Unknown;

        int limit = utf8.Length <= _probeLimit ? utf8.Length : _probeLimit;
        ReadOnlySpan<byte> head = utf8[..limit];

        int cutoff = limit / 10 + 1;
        int controls = 0;
        byte firstNonWhitespace = 0;
        bool foundFirstNonWhitespace = false;

        for (int i = 0; i < head.Length; i++)
        {
            byte b = head[i];

            if (b == 0)
                return ContentKind.Binary;

            if (b < 0x20)
            {
                if (b != (byte)'\t' && b != (byte)'\n' && b != (byte)'\r')
                {
                    if (++controls >= cutoff)
                        return ContentKind.Binary;
                }

                continue;
            }

            if (!foundFirstNonWhitespace && b != (byte)' ')
            {
                firstNonWhitespace = b;
                foundFirstNonWhitespace = true;
            }
        }

        if (!foundFirstNonWhitespace)
            return utf8.Length == head.Length ? ContentKind.Unknown : ContentKind.Text;

        return firstNonWhitespace switch
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
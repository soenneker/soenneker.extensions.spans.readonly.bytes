[![](https://img.shields.io/nuget/v/soenneker.extensions.spans.readonly.bytes.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.spans.readonly.bytes/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.spans.readonly.bytes/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.spans.readonly.bytes/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.extensions.spans.readonly.bytes.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.spans.readonly.bytes/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.spans.readonly.bytes/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.spans.readonly.bytes/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Extensions.Spans.Readonly.Bytes
Allocation-conscious SHA-256, ASCII comparison, and content-sniffing helpers for `ReadOnlySpan<byte>`.

## Installation

```bash
dotnet add package Soenneker.Extensions.Spans.Readonly.Bytes
```

## SHA-256 as hexadecimal text

```csharp
using Soenneker.Extensions.Spans.Readonly.Bytes;

ReadOnlySpan<byte> data = "payload"u8;

string upper = data.ToSha256Hex();
string lower = data.ToSha256Hex(upperCase: false);

Span<char> destination = stackalloc char[64];
bool written = data.TryWriteSha256Hex(destination, upperCase: false, out int charsWritten);
```

`ToSha256Hex()` returns exactly 64 characters. `TryWriteSha256Hex()` avoids the result-string allocation, requires a destination of at least 64 characters, and reports `charsWritten = 0` without modifying the destination when it is too small.

## Classify an unknown payload

```csharp
using Soenneker.Enums.ContentKinds;
using Soenneker.Extensions.Spans.Readonly.Bytes;

ReadOnlySpan<byte> payload = "  {\"id\": 42}"u8;

ContentKind kind = payload.Classify();
bool looksLikeJson = payload.LooksLikeJson();
```

Classification is deliberately a cheap sniff, not parsing or validation. It examines at most the first 512 bytes, skips a leading UTF-8 BOM, treats a null byte or a high density of control bytes as binary, and otherwise uses the first non-whitespace byte to choose JSON, XML/HTML, or text. JSON scalar prefixes such as a quote, digit, `-`, `t`, `f`, or `n` are recognized.

Use a real JSON/XML parser before trusting or processing untrusted content. UTF-8 validity is not checked, and `XmlOrHtml` does not distinguish the two formats.

## ASCII helpers

```csharp
bool equal = "CONTENT-TYPE"u8.Utf8AsciiEqualsIgnoreCase("content-type"u8);
bool containsUtf8 = "café"u8.ContainsNonAscii();
```

`Utf8AsciiEqualsIgnoreCase()` compares ASCII letters without culture rules. It does not validate that either input is ASCII; non-letter bytes must match exactly. `ContainsNonAscii()` simply detects bytes from `0x80` through `0xFF` and does not validate UTF-8.

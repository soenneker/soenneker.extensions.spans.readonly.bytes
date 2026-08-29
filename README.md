[![](https://img.shields.io/nuget/v/soenneker.extensions.spans.readonly.bytes.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.spans.readonly.bytes/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.spans.readonly.bytes/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.spans.readonly.bytes/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.extensions.spans.readonly.bytes.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.spans.readonly.bytes/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.spans.readonly.bytes/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.spans.readonly.bytes/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Extensions.Spans.Readonly.Bytes
A collection of helpful ReadOnlySpan (byte) extension methods.

## Installation

```bash
dotnet add package Soenneker.Extensions.Spans.Readonly.Bytes
```

## Quick start

```csharp
using Soenneker.Extensions.Spans.Readonly.Bytes;

// Given an existing ReadOnlySpan<byte> named data:
var result = data.ToSha256Hex();
```

## Common operations

- `ToSha256Hex()` - Computes the SHA-256 hash of the specified byte span and returns its hexadecimal representation.
- `TryWriteSha256Hex()` - Computes the SHA-256 hash of the specified byte span and writes its hexadecimal representation into a destination buffer. Returns `true` if the hash was successfully written to `destination`; otherwise, `false` if the destination buffer was too small or hashing failed. This method performs no managed heap allocations.
- `LooksLikeJson()` - Determines whether the specified UTF-8 byte span appears to represent JSON content. This method performs a lightweight check and does not fully validate the JSON structure.
- `LooksLikeXmlOrHtml()` - Determines whether the specified UTF-8 byte span appears to contain XML or HTML content.
- `LooksBinary()` - Determines whether the specified UTF-8 byte span appears to contain binary (non-text) content.
- `ContainsNonAscii()` - Determines whether the specified byte span contains any non-ASCII bytes.
- `Utf8AsciiEqualsIgnoreCase()` - Performs a case-insensitive comparison of two ASCII byte spans. Returns `true` if the spans are equal using ASCII case-insensitive comparison; otherwise, `false`.
- `Classify()` - Classifies the specified UTF-8 byte span into a high-level content category. Returns a `ContentKind` value indicating the detected content category.

using System;
using System.Security.Cryptography;
using AwesomeAssertions;
using Soenneker.Enums.ContentKinds;

namespace Soenneker.Extensions.Spans.Readonly.Bytes.Tests;

public class PerformanceRegressionTests
{
    [Test]
    public void Hash_hex_matches_runtime_and_respects_destination_boundaries()
    {
        var random = new Random(47);
        foreach (int length in new[] { 0, 1, 31, 32, 63, 64, 65, 512, 4096 })
        {
            byte[] data = new byte[length];
            random.NextBytes(data);
            ReadOnlySpan<byte> input = data;
            foreach (bool upper in new[] { true, false })
            {
                string expected = upper ? Convert.ToHexString(SHA256.HashData(data)) : Convert.ToHexStringLower(SHA256.HashData(data));
                input.ToSha256Hex(upper).Should().Be(expected);
                char[] destination = new string('?', 70).ToCharArray();
                input.TryWriteSha256Hex(destination, upper, out int written).Should().BeTrue();
                written.Should().Be(64);
                new string(destination, 0, 64).Should().Be(expected);
                new string(destination, 64, 6).Should().Be("??????");
                input.TryWriteSha256Hex(destination.AsSpan(0, 63), upper, out written).Should().BeFalse();
                written.Should().Be(0);
            }
        }
    }

    [Test]
    public void Classification_preserves_probe_and_control_boundaries()
    {
        ((ReadOnlySpan<byte>)"  {  }"u8).Classify().Should().Be(ContentKind.Json);
        ((ReadOnlySpan<byte>)"\t<xml>"u8).Classify().Should().Be(ContentKind.XmlOrHtml);
        ((ReadOnlySpan<byte>)" \0 text"u8).Classify().Should().Be(ContentKind.Binary);
        ((ReadOnlySpan<byte>)new byte[] { 0xef, 0xbb, 0xbf }).Classify().Should().Be(ContentKind.Unknown);
        byte[] data = new byte[513];
        Array.Fill(data, (byte)' ');
        ((ReadOnlySpan<byte>)data.AsSpan(0, 512)).Classify().Should().Be(ContentKind.Unknown);
        ((ReadOnlySpan<byte>)data).Classify().Should().Be(ContentKind.Text);
        data[512] = 0;
        ((ReadOnlySpan<byte>)data).Classify().Should().Be(ContentKind.Text);
        data[511] = 0;
        ((ReadOnlySpan<byte>)data).Classify().Should().Be(ContentKind.Binary);
    }
}

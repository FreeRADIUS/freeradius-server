using System.Buffers.Binary;
using System.Text;
using FreeRadius.Interop;

namespace JsonSmoke;

/// <summary>
/// Positive and negative tests for <see cref="RadiusRequestBlob.Parse"/>.
/// </summary>
/// <remarks>
/// Invoked from <see cref="Program"/> and from the NUnit project via the same source files.
/// </remarks>
internal static class RadiusRequestBlobParseTests
{
	/// <summary>Runs every test; throws on failure.</summary>
	public static void RunAll()
	{
		AssertProtocolConstants();
		RunPositiveTests();
		RunNegativeTests();
	}

	static void AssertProtocolConstants()
	{
		if (RDb1BlobBuilder.ExpectedHeaderSize != 12)
			throw new Exception($"unexpected ExpectedHeaderSize: {RDb1BlobBuilder.ExpectedHeaderSize}");
		if (RadiusRequestBlob.HeaderSize != RDb1BlobBuilder.ExpectedHeaderSize)
			throw new Exception(
				$"RadiusRequestBlob.HeaderSize is {RadiusRequestBlob.HeaderSize}, expected {RDb1BlobBuilder.ExpectedHeaderSize}");
	}

	static void RunPositiveTests()
	{
		TestMinimalFourLists();
		TestMinimalWithNonZeroHeaderFlags();
		TestWithProxySixLists();
	}

	static void TestMinimalFourLists()
	{
		byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
		RadiusRequest req = RadiusRequestBlob.Parse(blob);
		if (req.Section != "authorize")
			throw new Exception("unexpected section");
		if (req.Packet.Count != 0 || req.Reply.Count != 0 || req.Config.Count != 0 || req.SessionState.Count != 0)
			throw new Exception("expected empty standard lists");
		if (req.ProxyRequest.Count != 0 || req.ProxyReply.Count != 0)
			throw new Exception("expected empty proxy lists");
		Console.WriteLine("  minimal v1 (4 lists): OK");
	}

	static void TestMinimalWithNonZeroHeaderFlags()
	{
		const ushort flags = 0x00AB;
		byte[] blob = RDb1BlobBuilder.BuildMinimal("authenticate", headerFlags: flags);
		RadiusRequest req = RadiusRequestBlob.Parse(blob);
		if (req.Section != "authenticate")
			throw new Exception("unexpected section with non-zero header flags");
		Console.WriteLine($"  minimal v1 with header flags 0x{flags:X4}: OK");
	}

	static void TestWithProxySixLists()
	{
		byte[] blob = RDb1BlobBuilder.BuildWithProxy("pre_proxy");
		RadiusRequest req = RadiusRequestBlob.Parse(blob);
		if (req.Section != "pre_proxy")
			throw new Exception("unexpected section for proxy blob");
		if (req.Packet.Count != 0 || req.Reply.Count != 0 || req.Config.Count != 0 || req.SessionState.Count != 0)
			throw new Exception("expected empty standard lists");
		if (req.ProxyRequest.Count != 0 || req.ProxyReply.Count != 0)
			throw new Exception("expected empty proxy lists");
		Console.WriteLine("  minimal v1 (6 lists, WITH_PROXY layout): OK");
	}

	static void RunNegativeTests()
	{
		ExpectParseFailure("invalid magic", () =>
		{
			byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
			blob[2] = (byte)'x';
			RadiusRequestBlob.Parse(blob);
		});

		ExpectParseFailure("unsupported version", () =>
		{
			byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
			BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(4, 2), (ushort)(RadiusRequestBlob.FormatVersion + 1));
			RadiusRequestBlob.Parse(blob);
		});

		ExpectParseFailure("incorrect payload length", () =>
		{
			byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
			BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(8, 4),
				BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(8, 4)) + 1);
			RadiusRequestBlob.Parse(blob);
		});

		ExpectParseFailure("blob shorter than header", () =>
		{
			byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
			RadiusRequestBlob.Parse(blob.AsSpan(0, RadiusRequestBlob.HeaderSize - 1));
		});

		ExpectParseFailure("truncated section", () =>
		{
			byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
			int trim = 4;
			RadiusRequestBlob.Parse(blob.AsSpan(0, blob.Length - trim));
		});

		ExpectParseFailure("invalid num_lists", () =>
		{
			byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
			int numListsOffset = RadiusRequestBlob.HeaderSize + 2 + Encoding.UTF8.GetByteCount("authorize"); /* after section */
			BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(numListsOffset, 2), 5);
			RadiusRequestBlob.Parse(blob);
		});

		ExpectParseFailure("truncated vp_count", () =>
		{
			byte[] blob = RDb1BlobBuilder.BuildMinimal("authorize");
			RadiusRequestBlob.Parse(blob.AsSpan(0, blob.Length - 2));
		});

		ExpectParseFailure("truncated vp record", () =>
		{
			byte[] full = RDb1BlobBuilder.BuildMinimal("authorize");
			byte[] sectionUtf8 = Encoding.UTF8.GetBytes("authorize");
			int payloadLen = 2 + sectionUtf8.Length + 2 + 4 + 4;
			int total = RadiusRequestBlob.HeaderSize + payloadLen;
			byte[] blob = new byte[total];
			int o = 0;
			blob[o++] = (byte)'R';
			blob[o++] = (byte)'D';
			blob[o++] = (byte)'b';
			blob[o++] = (byte)'1';
			BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(o), RadiusRequestBlob.FormatVersion);
			o += 2;
			BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(o), 0);
			o += 2;
			BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(o), (uint)payloadLen);
			o += 4;
			BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(o), (ushort)sectionUtf8.Length);
			o += 2;
			sectionUtf8.CopyTo(blob.AsSpan(o));
			o += sectionUtf8.Length;
			BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(o), 4);
			o += 2;
			BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(o), 1);
			o += 4;
			RadiusRequestBlob.Parse(blob);
		});

		Console.WriteLine("  negative cases (8): OK");
	}

	/// <summary>
	/// Asserts <paramref name="action"/> throws <see cref="InvalidDataException"/> (parser failure).
	/// </summary>
	internal static void ExpectParseFailure(string caseName, Action action)
	{
		try
		{
			action();
			throw new Exception($"[{caseName}] expected InvalidDataException");
		}
		catch (InvalidDataException)
		{
			/* expected */
		}
		catch (Exception ex)
		{
			throw new Exception($"[{caseName}] expected InvalidDataException, got {ex.GetType().Name}: {ex.Message}", ex);
		}
	}
}

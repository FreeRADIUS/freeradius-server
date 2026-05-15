using System.Buffers.Binary;
using System.Text;
using FreeRadius.Interop;

namespace JsonSmoke;

/// <summary>
/// Builds synthetic <c>RDb1</c> v1 request blobs for <see cref="RadiusRequestBlob.Parse"/> tests.
/// </summary>
internal static class RDb1BlobBuilder
{
	/// <summary>Expected fixed header size (must match <see cref="RadiusRequestBlob.HeaderSize"/>).</summary>
	public const int ExpectedHeaderSize = 12;

	/// <summary>
	/// Minimal valid blob: four empty VP lists (non-<c>WITH_PROXY</c> layout).
	/// </summary>
	public static byte[] BuildMinimal(string section, ushort headerFlags = 0)
	{
		return Build(section, numLists: 4, headerFlags: headerFlags);
	}

	/// <summary>
	/// Minimal valid blob: six empty VP lists (proxy request + proxy reply included).
	/// </summary>
	public static byte[] BuildWithProxy(string section, ushort headerFlags = 0)
	{
		return Build(section, numLists: 6, headerFlags: headerFlags);
	}

	/// <summary>
	/// Constructs a complete <c>RDb1</c> buffer with <paramref name="numLists"/> empty lists.
	/// </summary>
	/// <param name="section">Section name (UTF-8).</param>
	/// <param name="numLists">4 (standard) or 6 (with proxy lists).</param>
	/// <param name="headerFlags">16-bit flags in the header (currently ignored by the parser).</param>
	public static byte[] Build(string section, ushort numLists, ushort headerFlags = 0)
	{
		if (numLists != 4 && numLists != 6)
			throw new ArgumentOutOfRangeException(nameof(numLists), numLists, "numLists must be 4 or 6");

		byte[] sectionUtf8 = Encoding.UTF8.GetBytes(section);
		if (sectionUtf8.Length > ushort.MaxValue)
			throw new ArgumentException("section too long", nameof(section));

		int payloadLen = 2 + sectionUtf8.Length + 2 + numLists * 4;
		int total = RadiusRequestBlob.HeaderSize + payloadLen;
		byte[] buf = new byte[total];
		int o = 0;
		buf[o++] = (byte)'R';
		buf[o++] = (byte)'D';
		buf[o++] = (byte)'b';
		buf[o++] = (byte)'1';
		BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o), RadiusRequestBlob.FormatVersion);
		o += 2;
		BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o), headerFlags);
		o += 2;
		BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(o), (uint)payloadLen);
		o += 4;
		BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o), (ushort)sectionUtf8.Length);
		o += 2;
		sectionUtf8.CopyTo(buf.AsSpan(o));
		o += sectionUtf8.Length;
		BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o), numLists);
		o += 2;
		for (int i = 0; i < numLists; i++)
		{
			BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(o), 0);
			o += 4;
		}

		if (o != total)
			throw new InvalidOperationException($"blob size mismatch: wrote {o}, expected {total}");
		return buf;
	}

	/// <summary>Returns a mutable copy of <paramref name="blob"/> for negative tests.</summary>
	public static byte[] Clone(byte[] blob) => (byte[])blob.Clone();
}

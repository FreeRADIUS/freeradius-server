using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace FreeRadius.Interop;

/// <summary>
/// Encoder for the <c>RDr1</c> v1 binary reply format consumed by <c>rlm_dotnet</c>.
/// </summary>
/// <remarks>
/// <para><b>Header (12 bytes, big-endian):</b> magic <c>RDr1</c>, version, flags, payload length.</para>
/// <para><b>Payload:</b> VP count (u32) followed by VP records using the same layout as request blobs.</para>
/// <para>
/// Return the byte array from <see cref="Encode"/> via <see cref="RadiusReply.FromBlob"/> in async policies.
/// Native code applies attributes to <c>request-&gt;reply</c> according to <see cref="FlagTargetReply"/>
/// and <see cref="FlagMerge"/>.
/// </para>
/// <para>
/// Build <see cref="RadiusVp"/> instances with correct <see cref="RadiusVp.DataType"/> and
/// <see cref="RadiusVp.RawValue"/> bytes (big-endian integers, etc.) for lossless encoding.
/// </para>
/// </remarks>
/// <seealso cref="RadiusReplyFormat.ReplyBlobV1"/>
public static class RadiusReplyBlob
{
	/// <summary>Size of the fixed <c>RDr1</c> header in bytes.</summary>
	public const int HeaderSize = 12;

	/// <summary>Supported reply blob version (must match native decoder).</summary>
	public const ushort FormatVersion = 1;

	/// <summary>Flag bit 0: attributes target the request reply list (always set for normal policies).</summary>
	public const ushort FlagTargetReply = 0x01;

	/// <summary>
	/// Flag bit 1: merge into existing reply attributes. When cleared, native code replaces the reply list.
	/// </summary>
	public const ushort FlagMerge = 0x02;

	/// <summary>
	/// Default operator for reply attributes: FreeRADIUS <c>T_OP_SET</c> (<c>:=</c>) from <c>token.h</c>.
	/// </summary>
	public const byte DefaultReplyOp = 11;

	/// <summary>
	/// Builds a string-valued VP suitable for <see cref="Encode"/>.
	/// </summary>
	/// <param name="name">Dictionary attribute name.</param>
	/// <param name="value">UTF-8 string value.</param>
	/// <param name="op">Comparison/assignment operator (default <see cref="DefaultReplyOp"/>).</param>
	/// <param name="tag">Attribute tag, or -1 when unused.</param>
	public static RadiusVp FromString(string name, string value, byte op = DefaultReplyOp, sbyte tag = -1) =>
		new RadiusVp
		{
			Name = name,
			Tag = tag,
			Op = op,
			WireFlags = RadiusVpWireFlags.None,
			DataType = PwType.String,
			RawValue = Encoding.UTF8.GetBytes(value ?? ""),
		};

	/// <summary>
	/// Builds a 32-bit unsigned integer VP (big-endian on the wire).
	/// </summary>
	/// <param name="name">Dictionary attribute name.</param>
	/// <param name="value">Integer value.</param>
	/// <param name="op">Comparison/assignment operator (default <see cref="DefaultReplyOp"/>).</param>
	/// <param name="tag">Attribute tag, or -1 when unused.</param>
	public static RadiusVp FromUInt32(string name, uint value, byte op = DefaultReplyOp, sbyte tag = -1)
	{
		byte[] raw = new byte[4];
		BinaryPrimitives.WriteUInt32BigEndian(raw, value);
		return new RadiusVp
		{
			Name = name,
			Tag = tag,
			Op = op,
			WireFlags = RadiusVpWireFlags.None,
			DataType = PwType.Integer,
			RawValue = raw,
		};
	}

	/// <summary>
	/// Builds an IPv4 address VP (four octets, network byte order).
	/// </summary>
	/// <param name="name">Dictionary attribute name (e.g. <c>Framed-IP-Address</c>).</param>
	/// <param name="address">IPv4 address string or <see cref="IPAddress"/>.</param>
	/// <param name="op">Comparison/assignment operator (default <see cref="DefaultReplyOp"/>).</param>
	/// <param name="tag">Attribute tag, or -1 when unused.</param>
	/// <exception cref="ArgumentException"><paramref name="address"/> is not IPv4.</exception>
	public static RadiusVp FromIpv4(string name, string address, byte op = DefaultReplyOp, sbyte tag = -1) =>
		FromIpv4(name, IPAddress.Parse(address), op, tag);

	/// <summary>
	/// Builds an IPv4 address VP from a parsed <see cref="IPAddress"/>.
	/// </summary>
	/// <param name="name">Dictionary attribute name.</param>
	/// <param name="address">IPv4 address.</param>
	/// <param name="op">Comparison/assignment operator (default <see cref="DefaultReplyOp"/>).</param>
	/// <param name="tag">Attribute tag, or -1 when unused.</param>
	/// <exception cref="ArgumentException"><paramref name="address"/> is not IPv4.</exception>
	public static RadiusVp FromIpv4(string name, IPAddress address, byte op = DefaultReplyOp, sbyte tag = -1)
	{
		if (address.AddressFamily != AddressFamily.InterNetwork)
			throw new ArgumentException("address must be IPv4", nameof(address));
		return new RadiusVp
		{
			Name = name,
			Tag = tag,
			Op = op,
			WireFlags = RadiusVpWireFlags.None,
			DataType = PwType.Ipv4Addr,
			RawValue = address.GetAddressBytes(),
		};
	}

	/// <summary>
	/// Encodes a list of VPs as a complete <c>RDr1</c> buffer (header + payload).
	/// </summary>
	/// <param name="vps">Attributes to add or replace in the reply list.</param>
	/// <param name="flags">
	/// Header flags; default is <see cref="FlagTargetReply"/> | <see cref="FlagMerge"/>.
	/// </param>
	/// <returns>Byte array suitable for <see cref="RadiusReply.FromBlob"/>.</returns>
	/// <exception cref="InvalidOperationException">Name or value exceeds wire limits.</exception>
	public static byte[] Encode(IReadOnlyList<RadiusVp> vps, ushort flags = FlagTargetReply | FlagMerge)
	{
		int payloadLen = 4;
		foreach (RadiusVp vp in vps) payloadLen += EstimateVpSize(vp);

		int total = HeaderSize + payloadLen;
		byte[] buf = new byte[total];
		int p = 0;

		buf[p++] = (byte)'R';
		buf[p++] = (byte)'D';
		buf[p++] = (byte)'r';
		buf[p++] = (byte)'1';
		BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(p, 2), FormatVersion);
		p += 2;
		BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(p, 2), flags);
		p += 2;
		BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(p, 4), (uint)payloadLen);
		p += 4;

		BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(p, 4), (uint)vps.Count);
		p += 4;
		foreach (RadiusVp vp in vps)
			p += WriteVp(buf.AsSpan(p), vp);

		if (p != total)
			throw new InvalidOperationException("encoding size mismatch");

		return buf;
	}

	/// <summary>Estimates serialized size of one VP record.</summary>
	static int EstimateVpSize(RadiusVp vp)
	{
		int nameLen = Encoding.UTF8.GetByteCount(vp.Name);
		return 2 + nameLen + 6 + 4 + vp.RawValue.Length;
	}

	/// <summary>Writes one VP record to <paramref name="dest"/>; returns bytes written.</summary>
	static int WriteVp(Span<byte> dest, RadiusVp vp)
	{
		int p = 0;
		byte[] nameBytes = Encoding.UTF8.GetBytes(vp.Name);
		if (nameBytes.Length > ushort.MaxValue)
			throw new InvalidOperationException("attribute name too long");

		BinaryPrimitives.WriteUInt16BigEndian(dest.Slice(p, 2), (ushort)nameBytes.Length);
		p += 2;
		nameBytes.CopyTo(dest.Slice(p));
		p += nameBytes.Length;
		dest[p++] = unchecked((byte)vp.Tag);
		dest[p++] = vp.Op;
		dest[p++] = (byte)vp.WireFlags;
		dest[p++] = 0;
		BinaryPrimitives.WriteUInt16BigEndian(dest.Slice(p, 2), (ushort)vp.DataType);
		p += 2;
		ReadOnlySpan<byte> raw = vp.RawValue.Span;
		if ((ulong)raw.Length > uint.MaxValue)
			throw new InvalidOperationException("vp value too long");
		BinaryPrimitives.WriteUInt32BigEndian(dest.Slice(p, 4), (uint)raw.Length);
		p += 4;
		raw.CopyTo(dest.Slice(p));
		return p + raw.Length;
	}
}

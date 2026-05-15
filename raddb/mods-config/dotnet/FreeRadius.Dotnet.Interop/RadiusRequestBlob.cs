using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

namespace FreeRadius.Interop;

/// <summary>
/// Per-attribute wire flags in <c>RDb1</c> / <c>RDr1</c> VP records (must match <c>DOTNET_REQ_VFLAG_*</c> in <c>rlm_dotnet.c</c>).
/// </summary>
[Flags]
public enum RadiusVpWireFlags : byte
{
	/// <summary>No special encoding; <see cref="RadiusVp.RawValue"/> is the on-wire VP value bytes.</summary>
	None = 0,

	/// <summary>
	/// Value is an xlat template (<c>VT_XLAT</c>); <see cref="RadiusVp.RawValue"/> is UTF-8 text
	/// to be expanded by FreeRADIUS, not a literal attribute value.
	/// </summary>
	XlatTemplate = 0x01,
}

/// <summary>
/// FreeRADIUS attribute data types (<c>PW_TYPE_*</c> in <c>src/include/radius.h</c>).
/// </summary>
/// <remarks>
/// <para>
/// Numeric values and order must match the C enum. Used when interpreting
/// <see cref="RadiusVp.RawValue"/> and when encoding reply blobs.
/// </para>
/// <para>
/// For display/logging, prefer <see cref="RadiusVp.FormatValueForLog"/> rather than
/// re-implementing type-specific formatting.
/// </para>
/// </remarks>
public enum PwType : ushort
{
	/// <summary><c>PW_TYPE_INVALID</c> (0).</summary>
	Invalid = 0,

	/// <summary><c>PW_TYPE_STRING</c> (1) — printable string (UTF-8 on the wire in practice).</summary>
	String = 1,

	/// <summary><c>PW_TYPE_INTEGER</c> (2) — 32-bit unsigned integer, big-endian in blob.</summary>
	Integer = 2,

	/// <summary><c>PW_TYPE_IPV4ADDR</c> (3) — four octets.</summary>
	Ipv4Addr = 3,

	/// <summary><c>PW_TYPE_DATE</c> (4) — Unix time, 32-bit big-endian.</summary>
	Date = 4,

	/// <summary><c>PW_TYPE_ABINARY</c> (5) — Ascend binary filter format.</summary>
	Abinary = 5,

	/// <summary><c>PW_TYPE_OCTETS</c> (6) — opaque octets.</summary>
	Octets = 6,

	/// <summary><c>PW_TYPE_IFID</c> (7) — interface identifier (8 octets).</summary>
	Ifid = 7,

	/// <summary><c>PW_TYPE_IPV6ADDR</c> (8) — 16 octets.</summary>
	Ipv6Addr = 8,

	/// <summary><c>PW_TYPE_IPV6PREFIX</c> (9) — RFC 3162 IPv6 prefix.</summary>
	Ipv6Prefix = 9,

	/// <summary><c>PW_TYPE_BYTE</c> (10) — single octet.</summary>
	Byte = 10,

	/// <summary><c>PW_TYPE_SHORT</c> (11) — 16-bit unsigned, big-endian.</summary>
	Short = 11,

	/// <summary><c>PW_TYPE_ETHERNET</c> (12) — 6-octet MAC.</summary>
	Ethernet = 12,

	/// <summary><c>PW_TYPE_SIGNED</c> (13) — 32-bit signed integer, big-endian.</summary>
	Signed = 13,

	/// <summary><c>PW_TYPE_COMBO_IP_ADDR</c> (14) — IPv4/IPv6 combo address.</summary>
	ComboIpAddr = 14,

	/// <summary><c>PW_TYPE_TLV</c> (15) — type-length-value container.</summary>
	Tlv = 15,

	/// <summary><c>PW_TYPE_EXTENDED</c> (16) — extended attribute.</summary>
	Extended = 16,

	/// <summary><c>PW_TYPE_LONG_EXTENDED</c> (17) — long extended attribute.</summary>
	LongExtended = 17,

	/// <summary><c>PW_TYPE_EVS</c> (18) — extended VSA.</summary>
	Evs = 18,

	/// <summary><c>PW_TYPE_INTEGER64</c> (19) — 64-bit unsigned, big-endian.</summary>
	Integer64 = 19,

	/// <summary><c>PW_TYPE_IPV4_PREFIX</c> (20) — IPv4 prefix.</summary>
	Ipv4Prefix = 20,

	/// <summary><c>PW_TYPE_VSA</c> (21) — Vendor-Specific Attribute wrapper.</summary>
	Vsa = 21,

	/// <summary><c>PW_TYPE_TIMEVAL</c> (22) — seconds + microseconds.</summary>
	Timeval = 22,

	/// <summary><c>PW_TYPE_BOOLEAN</c> (23) — 0 or non-zero octet.</summary>
	Boolean = 23,

	/// <summary><c>PW_TYPE_COMBO_IP_PREFIX</c> (24) — combo IP prefix.</summary>
	ComboIpPrefix = 24,

	/// <summary><c>PW_TYPE_MAX</c> (25) — sentinel / upper bound in C headers.</summary>
	Max = 25,
}

/// <summary>
/// One RADIUS attribute (<c>fr_pair_t</c> / VALUE_PAIR) from a decoded request or reply list.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Name"/> is the dictionary name (e.g. <c>User-Name</c>). <see cref="Op"/> is the
/// raw comparison/assignment operator byte from FreeRADIUS (<c>fr_token_t</c>).
/// <see cref="Tag"/> is the optional tag byte (-1 if unused).
/// </para>
/// <para>
/// <see cref="RawValue"/> contains the exact bytes sent on the wire. Use it when you need
/// lossless round-tripping (for example when building <see cref="RadiusReplyBlob"/> replies).
/// </para>
/// </remarks>
public sealed class RadiusVp
{
	/// <summary>Dictionary attribute name (UTF-8), e.g. <c>User-Name</c>.</summary>
	public required string Name { get; init; }

	/// <summary>Attribute tag, or -1 (<c>0xFF</c> on wire) when no tag is set.</summary>
	public sbyte Tag { get; init; }

	/// <summary>Operator / comparison token as a single byte (FreeRADIUS <c>fr_token_t</c>).</summary>
	public byte Op { get; init; }

	/// <summary>Wire flags (<see cref="RadiusVpWireFlags.XlatTemplate"/> etc.).</summary>
	public RadiusVpWireFlags WireFlags { get; init; }

	/// <summary>Attribute data type (<c>PW_TYPE_*</c>).</summary>
	public PwType DataType { get; init; }

	/// <summary>Raw value octets exactly as encoded in the blob (not a display string).</summary>
	public ReadOnlyMemory<byte> RawValue { get; init; }

	/// <summary><c>true</c> when <see cref="WireFlags"/> includes <see cref="RadiusVpWireFlags.XlatTemplate"/>.</summary>
	public bool IsXlatTemplate => WireFlags.HasFlag(RadiusVpWireFlags.XlatTemplate);

	/// <summary>
	/// Formats <see cref="RawValue"/> for human-readable logging (debug output, examples).
	/// </summary>
	/// <returns>Display string; not suitable for cryptographic or authorization decisions.</returns>
	/// <remarks>
	/// XLAT templates return UTF-8 text. Integers, IP addresses, and MACs are decoded when possible;
	/// unknown or binary types fall back to hexadecimal.
	/// </remarks>
	public string FormatValueForLog()
	{
		if (IsXlatTemplate)
			return SafeUtf8(RawValue.Span);

		ReadOnlySpan<byte> s = RawValue.Span;
		try
		{
			return DataType switch
			{
				PwType.String => SafeUtf8(s),
				PwType.Integer when s.Length >= 4 => BinaryPrimitives.ReadUInt32BigEndian(s).ToString(CultureInfo.InvariantCulture),
				PwType.Byte when s.Length >= 1 => s[0].ToString(CultureInfo.InvariantCulture),
				PwType.Short when s.Length >= 2 => BinaryPrimitives.ReadUInt16BigEndian(s).ToString(CultureInfo.InvariantCulture),
				PwType.Signed when s.Length >= 4 => BinaryPrimitives.ReadInt32BigEndian(s).ToString(CultureInfo.InvariantCulture),
				PwType.Integer64 when s.Length >= 8 => BinaryPrimitives.ReadUInt64BigEndian(s).ToString(CultureInfo.InvariantCulture),
				PwType.Ipv4Addr when s.Length >= 4 => new IPAddress(s.Slice(0, 4).ToArray()).ToString(),
				PwType.Ipv6Addr when s.Length >= 16 => new IPAddress(s.Slice(0, 16).ToArray()).ToString(),
				PwType.Boolean when s.Length >= 1 => (s[0] != 0).ToString(),
				PwType.Date when s.Length >= 4 => BinaryPrimitives.ReadUInt32BigEndian(s).ToString(CultureInfo.InvariantCulture),
				PwType.Ethernet when s.Length >= 6 => Convert.ToHexString(s.Slice(0, 6).ToArray()),
				PwType.Octets or PwType.Abinary or PwType.Tlv or PwType.Extended or PwType.LongExtended or PwType.Evs or PwType.Vsa
					=> Convert.ToHexString(s.ToArray()),
				_ => s.Length == 0 ? "" : Convert.ToHexString(s.ToArray()),
			};
		}
		catch
		{
			return Convert.ToHexString(s.ToArray());
		}
	}

	/// <summary>Best-effort UTF-8 decode for logging; falls back to hex on invalid sequences.</summary>
	static string SafeUtf8(ReadOnlySpan<byte> span)
	{
		if (span.Length == 0) return "";
		try
		{
			return Encoding.UTF8.GetString(span);
		}
		catch
		{
			return Convert.ToHexString(span.ToArray());
		}
	}
}

/// <summary>
/// Immutable snapshot of RADIUS lists for one module invocation.
/// </summary>
/// <remarks>
/// <para>
/// Populated by <see cref="RadiusRequestBlob.Parse"/> from the native <c>RDb1</c> blob.
/// List order matches FreeRADIUS request structure:
/// </para>
/// <list type="number">
/// <item><description><see cref="Packet"/> — incoming packet attributes.</description></item>
/// <item><description><see cref="Reply"/> — reply list being built.</description></item>
/// <item><description><see cref="Config"/> — control/config items for this request.</description></item>
/// <item><description><see cref="SessionState"/> — session-state list.</description></item>
/// <item><description><see cref="ProxyRequest"/> / <see cref="ProxyReply"/> — present when server built with proxy support (six lists).</description></item>
/// </list>
/// <para>
/// <see cref="Section"/> names the unlang section (e.g. <c>authorize</c>, <c>accounting</c>).
/// </para>
/// </remarks>
public sealed class RadiusRequest
{
	/// <summary>Active virtual-server section name (UTF-8), e.g. <c>authorize</c>.</summary>
	public required string Section { get; init; }

	/// <summary>Request / packet attribute list.</summary>
	public required IReadOnlyList<RadiusVp> Packet { get; init; }

	/// <summary>Reply attribute list (may already contain attributes from prior modules).</summary>
	public required IReadOnlyList<RadiusVp> Reply { get; init; }

	/// <summary>Config (control) pairs for this request.</summary>
	public required IReadOnlyList<RadiusVp> Config { get; init; }

	/// <summary>Session-state list.</summary>
	public required IReadOnlyList<RadiusVp> SessionState { get; init; }

	/// <summary>Proxy request list (empty when blob has four lists only).</summary>
	public required IReadOnlyList<RadiusVp> ProxyRequest { get; init; }

	/// <summary>Proxy reply list (empty when blob has four lists only).</summary>
	public required IReadOnlyList<RadiusVp> ProxyReply { get; init; }
}

/// <summary>
/// Decoder for the <c>RDb1</c> v1 binary request format produced by <c>rlm_dotnet</c>.
/// </summary>
/// <remarks>
/// <para><b>Header layout (12 bytes, big-endian where noted):</b></para>
/// <list type="table">
/// <listheader><term>Offset</term><description>Field</description></listheader>
/// <item><term>0–3</term><description>Magic <c>RDb1</c> (ASCII)</description></item>
/// <item><term>4–5</term><description>Format version (<see cref="FormatVersion"/>)</description></item>
/// <item><term>6–7</term><description>Flags (reserved)</description></item>
/// <item><term>8–11</term><description>Payload length (excludes header)</description></item>
/// </list>
/// <para><b>Payload:</b> section name (u16 length + UTF-8), list count (u16), then for each list:
/// VP count (u32) followed by VP records (name, tag, op, flags, pw_type, value).</para>
/// <para>
/// Policy code normally receives <see cref="RadiusRequest"/> from the interop layer; call
/// <see cref="Parse"/> directly only for unit tests (see <c>JsonSmoke</c>).
/// </para>
/// </remarks>
public static class RadiusRequestBlob
{
	/// <summary>Size of the <c>RDb1</c> / <c>RDr1</c> fixed header in bytes.</summary>
	public const int HeaderSize = 12;

	/// <summary>Supported request blob version (must match native encoder).</summary>
	public const ushort FormatVersion = 1;

	/// <summary>
	/// Parses a complete <c>RDb1</c> v1 buffer into a <see cref="RadiusRequest"/>.
	/// </summary>
	/// <param name="data">Full blob including header.</param>
	/// <returns>Decoded request snapshot.</returns>
	/// <exception cref="InvalidDataException">Magic, version, length, or VP structure is invalid.</exception>
	public static RadiusRequest Parse(ReadOnlySpan<byte> data)
	{
		if (data.Length < HeaderSize)
			throw new InvalidDataException("request blob shorter than header");

		if (data[0] != (byte)'R' || data[1] != (byte)'D' || data[2] != (byte)'b' || data[3] != (byte)'1')
			throw new InvalidDataException("request blob bad magic (expected RDb1)");

		ushort version = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(4, 2));
		if (version != FormatVersion)
			throw new InvalidDataException("request blob unsupported format version: " + version);

		_ = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(6, 2)); /* flags */
		uint payloadLen = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(8, 4));
		if ((ulong)HeaderSize + payloadLen != (ulong)data.Length)
			throw new InvalidDataException($"request blob length mismatch: header says payload {payloadLen}, total {data.Length}");

		ReadOnlySpan<byte> p = data.Slice(HeaderSize);
		int sectionLen = (int)BinaryPrimitives.ReadUInt16BigEndian(p.Slice(0, 2));
		p = p.Slice(2);
		if (p.Length < sectionLen)
			throw new InvalidDataException("request blob truncated at section");
		string section = Encoding.UTF8.GetString(p.Slice(0, sectionLen));
		p = p.Slice(sectionLen);

		if (p.Length < 2)
			throw new InvalidDataException("request blob truncated at num_lists");
		ushort numLists = BinaryPrimitives.ReadUInt16BigEndian(p.Slice(0, 2));
		p = p.Slice(2);

		List<RadiusVp>[] lists = new List<RadiusVp>[numLists];
		for (int i = 0; i < numLists; i++)
		{
			if (p.Length < 4)
				throw new InvalidDataException("request blob truncated at vp_count");
			uint vpCount = BinaryPrimitives.ReadUInt32BigEndian(p.Slice(0, 4));
			p = p.Slice(4);
			List<RadiusVp> list = new List<RadiusVp>((int)Math.Min(vpCount, int.MaxValue));
			for (uint j = 0U; j < vpCount; j++)
			{
				ReadVp(ref p, out RadiusVp vp);
				list.Add(vp);
			}

			lists[i] = list;
		}

		if (!p.IsEmpty)
			throw new InvalidDataException("request blob trailing garbage");

		RadiusVp[] empty = Array.Empty<RadiusVp>();
		RadiusVp[] pkt, rep, cfg, st, prq, prp;
		if (numLists == 4)
		{
			pkt = lists[0].ToArray();
			rep = lists[1].ToArray();
			cfg = lists[2].ToArray();
			st = lists[3].ToArray();
			prq = empty;
			prp = empty;
		}
		else if (numLists == 6)
		{
			pkt = lists[0].ToArray();
			rep = lists[1].ToArray();
			cfg = lists[2].ToArray();
			st = lists[3].ToArray();
			prq = lists[4].ToArray();
			prp = lists[5].ToArray();
		}
		else
			throw new InvalidDataException("request blob num_lists must be 4 or 6, got " + numLists);

		return new RadiusRequest
		{
			Section = section,
			Packet = pkt,
			Reply = rep,
			Config = cfg,
			SessionState = st,
			ProxyRequest = prq,
			ProxyReply = prp,
		};
	}

	/// <summary>Reads one VP record from the front of <paramref name="p"/> and advances the span.</summary>
	static void ReadVp(ref ReadOnlySpan<byte> p, out RadiusVp vp)
	{
		if (p.Length < 2)
			throw new InvalidDataException("vp truncated (name_len)");
		ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(p.Slice(0, 2));
		p = p.Slice(2);
		if (p.Length < nameLen)
			throw new InvalidDataException("vp truncated (name)");
		string name = Encoding.UTF8.GetString(p.Slice(0, nameLen));
		p = p.Slice(nameLen);
		if (p.Length < 6)
			throw new InvalidDataException("vp truncated (meta)");
		sbyte tag = unchecked((sbyte)p[0]);
		byte op = p[1];
		RadiusVpWireFlags vflags = (RadiusVpWireFlags)p[2];
		_ = p[3]; /* reserved */
		PwType pwType = (PwType)BinaryPrimitives.ReadUInt16BigEndian(p.Slice(4, 2));
		p = p.Slice(6);
		if (p.Length < 4)
			throw new InvalidDataException("vp truncated (value_len)");
		uint valueLen = BinaryPrimitives.ReadUInt32BigEndian(p.Slice(0, 4));
		p = p.Slice(4);
		if (valueLen > int.MaxValue)
			throw new InvalidDataException("vp value too long");
		if (p.Length < valueLen)
			throw new InvalidDataException("vp truncated (value bytes)");
		int nBytes = (int)valueLen;
		byte[] raw = p.Slice(0, nBytes).ToArray();
		p = p.Slice(nBytes);
		vp = new RadiusVp
		{
			Name = name,
			Tag = tag,
			Op = op,
			WireFlags = vflags,
			DataType = pwType,
			RawValue = raw,
		};
	}
}

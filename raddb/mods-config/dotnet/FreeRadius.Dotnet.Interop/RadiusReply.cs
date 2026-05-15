namespace FreeRadius.Interop;

/// <summary>
/// Discriminator written to native <c>out_reply_format</c> when a policy returns via
/// <see cref="IAsyncRadiusPolicy"/>.
/// </summary>
/// <remarks>
/// Synchronous <see cref="IRadiusPolicy"/> always uses pair-list strings; only the async path
/// can select <see cref="ReplyBlobV1"/>.
/// </remarks>
public enum RadiusReplyFormat
{
	/// <summary>
	/// UTF-8 FreeRADIUS pair-list string (NUL-terminated in the native reply buffer).
	/// Example: <c>Reply-Message := "hello"</c>.
	/// </summary>
	PairListString = 0,

	/// <summary>
	/// Binary <c>RDr1</c> v1 blob (<see cref="RadiusReplyBlob"/>). Native code decodes VP records
	/// into the request reply list (merge or replace per blob flags).
	/// </summary>
	ReplyBlobV1 = 1,
}

/// <summary>
/// Structured reply from async policies; carries either a pair-list string or an <c>RDr1</c> blob.
/// </summary>
/// <remarks>
/// <para>
/// Construct with <see cref="FromPairList"/>, <see cref="FromBlob"/>, or <see cref="Empty"/>.
/// The interop layer copies data into the native reply buffer (size limited by
/// <c>reply_buffer_size</c> in radiusd.conf).
/// </para>
/// <para>
/// For sync policies, return a <c>string</c> from <see cref="IRadiusPolicy"/> methods instead;
/// the runtime wraps it as <see cref="RadiusReplyFormat.PairListString"/> automatically.
/// </para>
/// </remarks>
public sealed class RadiusReply
{
	/// <summary>How <see cref="PairList"/> or <see cref="Blob"/> should be interpreted.</summary>
	public required RadiusReplyFormat Format { get; init; }

	/// <summary>
	/// Pair-list assignments when <see cref="Format"/> is <see cref="RadiusReplyFormat.PairListString"/>.
	/// Use an empty string for no reply changes.
	/// </summary>
	public string PairList { get; init; } = "";

	/// <summary>
	/// <c>RDr1</c> payload when <see cref="Format"/> is <see cref="RadiusReplyFormat.ReplyBlobV1"/>.
	/// Typically produced by <see cref="RadiusReplyBlob.Encode"/>.
	/// </summary>
	public byte[]? Blob { get; init; }

	/// <summary>Creates a pair-list reply (default path for most policies).</summary>
	/// <param name="pairList">FreeRADIUS pair-list syntax, or <c>null</c> for empty.</param>
	/// <returns>A reply using <see cref="RadiusReplyFormat.PairListString"/>.</returns>
	public static RadiusReply FromPairList(string? pairList) => new()
	{
		Format = RadiusReplyFormat.PairListString,
		PairList = pairList ?? ""
	};

	/// <summary>Creates a binary <c>RDr1</c> reply.</summary>
	/// <param name="blob">Encoded bytes from <see cref="RadiusReplyBlob.Encode"/>.</param>
	/// <returns>A reply using <see cref="RadiusReplyFormat.ReplyBlobV1"/>.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="blob"/> is <c>null</c>.</exception>
	public static RadiusReply FromBlob(byte[] blob) => new()
	{
		Format = RadiusReplyFormat.ReplyBlobV1,
		Blob = blob ?? throw new ArgumentNullException(nameof(blob))
	};

	/// <summary>Pair-list reply with no attribute changes (<see cref="PairList"/> is empty).</summary>
	public static readonly RadiusReply Empty = FromPairList(IRadiusPolicy.EmptyReply);
}

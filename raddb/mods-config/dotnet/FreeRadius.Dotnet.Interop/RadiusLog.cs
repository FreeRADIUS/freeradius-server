namespace FreeRadius.Interop;

/// <summary>
/// Log level constants passed to the <c>Action&lt;int, string&gt;</c> radlog delegate
/// from your policy constructor.
/// </summary>
/// <remarks>
/// <para>
/// Values match FreeRADIUS v3 <c>log_type_t</c> in <c>src/include/log.h</c>. They are forwarded
/// unchanged to the native <c>radlog</c> function pointer supplied in the boot JSON.
/// </para>
/// <para>
/// <b>Debug visibility:</b> whether <see cref="Dbg"/>, <see cref="DbgWarn"/>, and related levels
/// appear in logs is determined by the server (typically <c>radiusd -X</c>), not by this SDK.
/// The interop layer does not currently expose a <c>DebugEnabled</c> flag; if one is added later,
/// it would only gate managed-side formatting—the native module would still filter by server
/// configuration.
/// </para>
/// <para><b>Example</b> (store the delegate from your policy constructor):</para>
/// <code>
/// public sealed class MyPolicy : IRadiusPolicy
/// {
///     readonly Action&lt;int, string&gt;? _radlog;
///
///     public MyPolicy(Action&lt;int, string&gt;? radlog, string instanceName, JsonElement extra)
///     {
///         _radlog = radlog;
///     }
///
///     void Log(int level, string message) => _radlog?.Invoke(level, message);
///
///     public (int Rcode, string ReplyPairList) Authorize(RadiusRequest request)
///     {
///         Log(RadiusLog.Dbg, "authorize User-Name=" + request.Packet.FirstOrDefault()?.Name);
///         return (RlmRcode.Ok, IRadiusPolicy.EmptyReply);
///     }
/// }
/// </code>
/// </remarks>
public static class RadiusLog
{
	/// <summary><c>L_AUTH</c> (2) — authentication-related message.</summary>
	public const int Auth = 2;

	/// <summary><c>L_INFO</c> (3) — informational.</summary>
	public const int Info = 3;

	/// <summary><c>L_ERR</c> (4) — error.</summary>
	public const int Err = 4;

	/// <summary><c>L_WARN</c> (5) — warning.</summary>
	public const int Warn = 5;

	/// <summary><c>L_PROXY</c> (6) — proxy-related.</summary>
	public const int Proxy = 6;

	/// <summary><c>L_ACCT</c> (7) — accounting-related.</summary>
	public const int Acct = 7;

	/// <summary><c>L_DBG</c> (16) — debug (visible with <c>radiusd -X</c>).</summary>
	public const int Dbg = 16;

	/// <summary><c>L_DBG_WARN</c> (17) — debug warning.</summary>
	public const int DbgWarn = 17;

	/// <summary><c>L_DBG_ERR</c> (18) — debug error.</summary>
	public const int DbgErr = 18;

	/// <summary><c>L_DBG_WARN_REQ</c> (19) — debug warning including request context.</summary>
	public const int DbgWarnReq = 19;

	/// <summary><c>L_DBG_ERR_REQ</c> (20) — debug error including request context.</summary>
	public const int DbgErrReq = 20;
}

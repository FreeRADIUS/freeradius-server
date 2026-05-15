namespace FreeRadius.Interop;

/// <summary>
/// Contract for synchronous RADIUS policy handlers loaded by <c>rlm_dotnet</c>.
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface in a public class in your policy assembly. Configure
/// <c>policy_type</c> in <c>mods-available/dotnet</c> as
/// <c>"YourNamespace.YourPolicy, YourAssembly"</c> (standard .NET type name format).
/// </para>
/// <para>
/// The native module calls a single unmanaged entry point per request; managed code
/// routes to the method that matches <see cref="RadiusRequest.Section"/> (for example
/// <c>"authorize"</c> maps to <see cref="Authorize"/>).
/// </para>
/// <para>
/// <b>Return tuple:</b>
/// </para>
/// <list type="bullet">
/// <item><description><c>Rcode</c> — a <see cref="RlmRcode"/> constant (must match FreeRADIUS <c>rlm_rcode_t</c>).</description></item>
/// <item><description><c>ReplyPairList</c> — UTF-8 FreeRADIUS pair-list syntax applied to the reply list, or <see cref="EmptyReply"/> for no changes. Comma-separated assignments are supported, e.g. <c>Reply-Message := "accepted", Framed-IP-Address := 10.0.0.1</c>. Operators and quoting follow FreeRADIUS unlang/pair-list rules.</description></item>
/// </list>
/// <para>
/// Example: <c>return (RlmRcode.Ok, EmptyReply);</c> or
/// <c>return (RlmRcode.Ok, @"Reply-Message := ""hello""");</c>
/// </para>
/// <para>
/// For binary replies (faster, preserves raw VP encoding), implement <see cref="IAsyncRadiusPolicy"/>
/// and return <see cref="RadiusReply.FromBlob"/> instead of using this interface's string replies.
/// </para>
/// <para>
/// <b>Constructor injection:</b> if your policy exposes a public constructor
/// <c>(Action&lt;int, string&gt; radlog, string instanceName, JsonElement extra)</c>,
/// <c>rlm_dotnet</c> supplies the native log callback, the module instance name, and the
/// <c>extra_config</c> JSON object from radiusd.conf. Simpler constructors are also supported
/// (see <c>InteropImpl.CreatePolicy</c>).
/// </para>
/// </remarks>
/// <seealso cref="IAsyncRadiusPolicy"/>
/// <seealso cref="ExamplePolicy"/>
public interface IRadiusPolicy
{
	/// <summary>
	/// Empty pair-list: no reply attributes added (same as <c>""</c>).
	/// </summary>
	const string EmptyReply = "";

	/// <summary>
	/// Handles the <c>authorize</c> section (authentication/authorization policy).
	/// </summary>
	/// <param name="request">Decoded snapshot of packet, reply, config, session-state, and optional proxy lists.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	(int Rcode, string ReplyPairList) Authorize(RadiusRequest request);

	/// <summary>
	/// Handles the <c>authenticate</c> section (credential verification).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation delegates to <see cref="Authorize"/>.</remarks>
	(int Rcode, string ReplyPairList) Authenticate(RadiusRequest request) => Authorize(request);

	/// <summary>
	/// Handles the <c>preacct</c> section (pre-accounting).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation delegates to <see cref="Accounting"/>.</remarks>
	(int Rcode, string ReplyPairList) Preacct(RadiusRequest request) => Accounting(request);

	/// <summary>
	/// Handles the <c>accounting</c> section.
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty reply.</remarks>
	(int Rcode, string ReplyPairList) Accounting(RadiusRequest request) => (RlmRcode.Ok, EmptyReply);

	/// <summary>
	/// Handles the <c>session</c> section (session management / interim updates).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty reply.</remarks>
	(int Rcode, string ReplyPairList) Session(RadiusRequest request) => (RlmRcode.Ok, EmptyReply);

	/// <summary>
	/// Handles the <c>pre_proxy</c> section (before proxying).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty reply.</remarks>
	(int Rcode, string ReplyPairList) PreProxy(RadiusRequest request) => (RlmRcode.Ok, EmptyReply);

	/// <summary>
	/// Handles the <c>post_proxy</c> section (after proxy response).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty reply.</remarks>
	(int Rcode, string ReplyPairList) PostProxy(RadiusRequest request) => (RlmRcode.Ok, EmptyReply);

	/// <summary>
	/// Handles the <c>post_auth</c> section (after authentication).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty reply.</remarks>
	(int Rcode, string ReplyPairList) PostAuth(RadiusRequest request) => (RlmRcode.Ok, EmptyReply);

	/// <summary>
	/// Handles the <c>recv_coa</c> section (Change-of-Authorization received).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty reply.</remarks>
	(int Rcode, string ReplyPairList) RecvCoa(RadiusRequest request) => (RlmRcode.Ok, EmptyReply);

	/// <summary>
	/// Handles the <c>send_coa</c> section (Change-of-Authorization sent).
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <returns>Module result code and optional reply pair-list string.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty reply.</remarks>
	(int Rcode, string ReplyPairList) SendCoa(RadiusRequest request) => (RlmRcode.Ok, EmptyReply);
}

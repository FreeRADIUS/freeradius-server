using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Text.Json;

namespace FreeRadius.Interop;

/// <summary>
/// Reference policy for <c>rlm_dotnet</c>: logs all request attribute lists at debug level,
/// mirroring <c>rlm_python/example.py</c> and <c>mods-config/perl/example.pl</c>.
/// </summary>
/// <remarks>
/// <para>
/// Enable in <c>mods-available/dotnet</c> with:
/// <c>policy_type = "FreeRadius.Interop.ExamplePolicy, FreeRadius.Dotnet.Interop"</c>
/// after publishing the interop assembly. Run <c>radiusd -X</c> to see
/// <see cref="RadiusLog.Dbg"/> output from <see cref="LogRequestAttributes"/>.
/// </para>
/// <para>
/// Copy this class into your own assembly as a starting point, rename the namespace,
/// and implement real authorization logic in <see cref="Authorize"/>.
/// </para>
/// <para>
/// See <see cref="OkNoReply"/>, <see cref="OkReply"/>, and <see cref="Reject"/> for common
/// return patterns using <see cref="IRadiusPolicy.EmptyReply"/>.
/// </para>
/// <para>
/// This class also implements <see cref="IAsyncRadiusPolicy"/>; when loaded, the interop layer
/// uses async dispatch. Set <c>extra_config</c> property <c>async_demo_http_url</c> to a URL
/// (e.g. <c>https://httpbin.org/get</c>) to run an optional <see cref="HttpClient"/> GET in
/// <see cref="AuthorizeAsync"/> before the normal authorize logic. Use <c>async_timeout_ms</c>
/// in radiusd.conf to cap wait time.
/// </para>
/// <para><b>Further patterns</b> (see private <c>Example*</c> helpers in this file):</para>
/// <list type="bullet">
/// <item><description><see cref="ExampleBinaryReplyAsync"/> — <c>RDr1</c> reply via <see cref="RadiusReplyBlob"/></description></item>
/// <item><description><see cref="ExampleCoaReply"/> — <c>recv_coa</c> / <c>send_coa</c> pair-list reply</description></item>
/// <item><description><see cref="ExampleDatabaseAuthorizeAsync"/> — async SQL lookup skeleton</description></item>
/// </list>
/// </remarks>
/// <seealso cref="IRadiusPolicy"/>
/// <seealso cref="IAsyncRadiusPolicy"/>
public sealed class ExamplePolicy : IRadiusPolicy, IAsyncRadiusPolicy, IDisposable
{
	static readonly HttpClient AsyncDemoHttp = new() { Timeout = TimeSpan.FromSeconds(5) };

	/// <summary>
	/// Cached <see cref="RlmRcode.Ok"/> + <see cref="RadiusReply.Empty"/> (same as <see cref="IAsyncRadiusPolicy.EmptyResult"/>).
	/// </summary>
	static readonly (int Rcode, RadiusReply Reply) EmptyAsyncResult = IAsyncRadiusPolicy.EmptyResult;

	readonly Action<int, string>? _radlog;
	readonly string _instanceName;
	readonly JsonElement _extra;
	bool _disposed;

	/// <summary>
	/// Preferred constructor: receives native logging, instance name, and <c>extra_config</c> JSON.
	/// </summary>
	/// <param name="radlog">Callback to FreeRADIUS <c>radlog</c>; use <see cref="RadiusLog"/> levels. May be <c>null</c>.</param>
	/// <param name="instanceName">Module instance name from radiusd.conf.</param>
	/// <param name="extra">Parsed <c>extra_config</c> object (may be undefined JSON).</param>
	public ExamplePolicy(Action<int, string>? radlog, string instanceName, JsonElement extra)
	{
		_radlog = radlog;
		_instanceName = instanceName ?? "";
		_extra = extra;
	}

	/// <inheritdoc />
	/// <remarks>
	/// Logs the full request tree, then demonstrates reading <c>User-Name</c> from the packet list.
	/// Uncomment a different return in the method body to try accept/reject examples.
	/// </remarks>
	public (int Rcode, string ReplyPairList) Authorize(RadiusRequest request)
	{
		LogAllAttributes("authorize", request, includeBootExtras: true);

		if (TryGetVp(request.Packet, "User-Name", out RadiusVp? userName))
			Log(RadiusLog.Dbg, "authorize: User-Name = " + userName.FormatValueForLog());

		// Examples (replace OkNoReply with one of these while testing):
		// return OkReply(@"Reply-Message := ""accepted by ExamplePolicy""");
		// return OkReply(@"Reply-Message := ""hello"", Session-Timeout := 3600");
		// return Reject();
		// CoA sections: return ExampleCoaReply();
		return OkNoReply();
	}

	/// <inheritdoc />
	/// <remarks>
	/// Optional HTTP demo: reads <c>async_demo_http_url</c> from <c>extra_config</c>, performs
	/// <c>GET</c> with <see cref="AsyncDemoHttp"/>, then runs the same logic as <see cref="Authorize"/>.
	/// To try other patterns, return <c>await ExampleDatabaseAuthorizeAsync(request, cancellationToken)</c>
	/// or <c>await ExampleBinaryReplyAsync()</c> instead of the default path below.
	/// </remarks>
	public async ValueTask<(int Rcode, RadiusReply Reply)> AuthorizeAsync(RadiusRequest request, CancellationToken cancellationToken = default)
	{
		await RunOptionalHttpDemoAsync(cancellationToken).ConfigureAwait(false);

		// return await ExampleBinaryReplyAsync();
		// return await ExampleDatabaseAuthorizeAsync(request, cancellationToken);

		(int rcode, string pairList) = Authorize(request);
		return ToAsyncResult(rcode, pairList);
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) Authenticate(RadiusRequest request)
	{
		LogAllAttributes("authenticate", request, includeBootExtras: false);
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) Preacct(RadiusRequest request)
	{
		LogAllAttributes("preacct", request, includeBootExtras: false);
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) Accounting(RadiusRequest request)
	{
		LogAllAttributes("accounting", request, includeBootExtras: false);
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) Session(RadiusRequest request)
	{
		LogAllAttributes("session", request, includeBootExtras: false);
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) PreProxy(RadiusRequest request)
	{
		LogAllAttributes("pre_proxy", request, includeBootExtras: false);
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) PostProxy(RadiusRequest request)
	{
		LogAllAttributes("post_proxy", request, includeBootExtras: false);
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) PostAuth(RadiusRequest request)
	{
		LogAllAttributes("post_auth", request, includeBootExtras: false);
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) RecvCoa(RadiusRequest request)
	{
		LogAllAttributes("recv_coa", request, includeBootExtras: false);
		// return ExampleCoaReply();
		return OkNoReply();
	}

	/// <inheritdoc />
	public (int Rcode, string ReplyPairList) SendCoa(RadiusRequest request)
	{
		LogAllAttributes("send_coa", request, includeBootExtras: false);
		// return ExampleCoaReply();
		return OkNoReply();
	}

	/// <summary><see cref="RlmRcode.Ok"/> with <see cref="IRadiusPolicy.EmptyReply"/> (no reply attributes).</summary>
	static (int Rcode, string ReplyPairList) OkNoReply() => (RlmRcode.Ok, IRadiusPolicy.EmptyReply);

	/// <summary><see cref="RlmRcode.Ok"/> with a FreeRADIUS pair-list reply string.</summary>
	/// <param name="pairList">Pair-list syntax, e.g. <c>Reply-Message := "accepted"</c>.</param>
	static (int Rcode, string ReplyPairList) OkReply(string pairList) => (RlmRcode.Ok, pairList);

	/// <summary><see cref="RlmRcode.Reject"/> without adding reply attributes.</summary>
	static (int Rcode, string ReplyPairList) Reject() => (RlmRcode.Reject, IRadiusPolicy.EmptyReply);

	/// <summary>Maps a sync policy tuple to <see cref="IAsyncRadiusPolicy"/> return shape.</summary>
	static (int Rcode, RadiusReply Reply) ToAsyncResult(int rcode, string pairList)
	{
		if (pairList.Length == 0 || pairList == IRadiusPolicy.EmptyReply)
			return rcode == RlmRcode.Ok ? EmptyAsyncResult : (rcode, RadiusReply.Empty);
		return (rcode, RadiusReply.FromPairList(pairList));
	}

	/// <summary>Returns <see cref="EmptyAsyncResult"/> as a completed <see cref="ValueTask"/>.</summary>
	static ValueTask<(int Rcode, RadiusReply Reply)> OkAsyncNoReply() =>
		new ValueTask<(int Rcode, RadiusReply Reply)>(EmptyAsyncResult);

	/// <summary>
	/// Example: build an <c>RDr1</c> reply with <see cref="RadiusReplyBlob"/> (async policies only).
	/// </summary>
	/// <remarks>Call from <see cref="AuthorizeAsync"/> instead of <see cref="ToAsyncResult"/> to experiment.</remarks>
	static ValueTask<(int Rcode, RadiusReply Reply)> ExampleBinaryReplyAsync()
	{
		byte[] blob = RadiusReplyBlob.Encode(new[]
		{
			RadiusReplyBlob.FromString("Reply-Message", "accepted via RDr1"),
		});
		return new ValueTask<(int Rcode, RadiusReply Reply)>((RlmRcode.Ok, RadiusReply.FromBlob(blob)));
	}

	/// <summary>
	/// Example: pair-list reply suitable for <c>recv_coa</c> / <c>send_coa</c> sections (sync API).
	/// </summary>
	static (int Rcode, string ReplyPairList) ExampleCoaReply() =>
		OkReply(@"Reply-Message := ""CoA handled by ExamplePolicy""");

	/// <summary>
	/// Example: async database-style authorization skeleton (replace with real ADO.NET / EF / Dapper).
	/// </summary>
	/// <remarks>
	/// Reads <c>User-Name</c>, simulates a lookup with a short <c>Task.Delay</c>, then returns accept or reject.
	/// Configure connection strings in <c>extra_config</c> in a real policy.
	/// </remarks>
	static async ValueTask<(int Rcode, RadiusReply Reply)> ExampleDatabaseAuthorizeAsync(
		RadiusRequest request, CancellationToken cancellationToken)
	{
		if (!TryGetVp(request.Packet, "User-Name", out RadiusVp? userName))
			return (RlmRcode.Reject, RadiusReply.Empty);

		string name = userName.FormatValueForLog();
		await Task.Delay(10, cancellationToken).ConfigureAwait(false);

		// Placeholder: query your database for 'name' and map to RlmRcode + reply attributes.
		bool allowed = !string.IsNullOrEmpty(name);
		if (!allowed)
			return (RlmRcode.Reject, RadiusReply.Empty);

		return (RlmRcode.Ok, RadiusReply.FromPairList($@"Reply-Message := ""user {name} ok (db example)"""));
	}

	/// <summary>
	/// Demonstrates async I/O when <c>extra_config.async_demo_http_url</c> is set (debug only).
	/// </summary>
	async Task RunOptionalHttpDemoAsync(CancellationToken cancellationToken)
	{
		if (_extra.ValueKind != JsonValueKind.Object ||
		    !_extra.TryGetProperty("async_demo_http_url", out JsonElement urlEl) ||
		    urlEl.ValueKind != JsonValueKind.String)
			return;

		string? url = urlEl.GetString();
		if (string.IsNullOrWhiteSpace(url))
			return;

		try
		{
			using HttpResponseMessage response = await AsyncDemoHttp.GetAsync(url, cancellationToken).ConfigureAwait(false);
			Log(RadiusLog.Dbg, $"async_demo_http_url: {(int)response.StatusCode} {response.ReasonPhrase} ({url})");
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			Log(RadiusLog.Warn, "async_demo_http_url failed: " + ex.Message);
		}
	}

	/// <summary>Finds the first VP with the given dictionary name in a list.</summary>
	static bool TryGetVp(IReadOnlyList<RadiusVp> list, string name, [NotNullWhen(true)] out RadiusVp? vp)
	{
		foreach (RadiusVp item in list)
		{
			if (string.Equals(item.Name, name, StringComparison.Ordinal))
			{
				vp = item;
				return true;
			}
		}

		vp = null;
		return false;
	}

	/// <summary>Logs shutdown message when the module detaches (shared or per-thread instance).</summary>
	public void Dispose()
	{
		if (_disposed) return;
		_disposed = true;
		Log(RadiusLog.Info, "*** goodbye from ExamplePolicy (dotnet) ***");
	}

	/// <summary>
	/// Logs section banner at <see cref="RadiusLog.Info"/> and attribute tree at <see cref="RadiusLog.Dbg"/>.
	/// </summary>
	/// <param name="phase">Section name for messages.</param>
	/// <param name="request">Current request snapshot.</param>
	/// <param name="includeBootExtras">When <c>true</c>, also logs <c>extra_config</c> and instance name (authorize only).</param>
	void LogAllAttributes(string phase, RadiusRequest request, bool includeBootExtras)
	{
		try
		{
			Log(RadiusLog.Info, "*** " + phase + " ***");
			Log(RadiusLog.Info, "*** radlog (request tree, cf. rlm_perl log_request_attributes) ***");

			LogRequestAttributes(request);

			if (includeBootExtras && _extra.ValueKind != JsonValueKind.Undefined && _extra.ValueKind != JsonValueKind.Null)
				Log(RadiusLog.Dbg, "module extra (dotnet boot JSON \"extra\" object): " + _extra.GetRawText());

			if (includeBootExtras)
				Log(RadiusLog.Dbg, "instance_name: " + _instanceName);
		}
		catch (Exception ex)
		{
			_radlog?.Invoke(RadiusLog.Info, "dotnet ExamplePolicy: logging failed in " + phase + ": " + ex.Message);
		}
	}

	/// <summary>
	/// Logs <c>request:</c> header and each VP list (packet, reply, config, session_state, proxy lists).
	/// </summary>
	/// <param name="request">Decoded request.</param>
	void LogRequestAttributes(RadiusRequest request)
	{
		string pad2 = new string(' ', 2);
		Log(RadiusLog.Dbg, "request:");
		Log(RadiusLog.Dbg, pad2 + "section = " + request.Section);
		LogVpList("packet", request.Packet, 2);
		LogVpList("reply", request.Reply, 2);
		LogVpList("config", request.Config, 2);
		LogVpList("session_state", request.SessionState, 2);
		LogVpList("proxy_request", request.ProxyRequest, 2);
		LogVpList("proxy_reply", request.ProxyReply, 2);
	}

	/// <summary>Logs one attribute list with Perl-style indentation.</summary>
	/// <param name="listName">List label (e.g. <c>packet</c>).</param>
	/// <param name="list">Attributes in that list.</param>
	/// <param name="baseIndent">Spaces before list name.</param>
	void LogVpList(string listName, IReadOnlyList<RadiusVp> list, int baseIndent)
	{
		string pad = new string(' ', baseIndent);
		foreach (RadiusVp vp in list)
		{
			Log(RadiusLog.Dbg, pad + listName + " =>");
			Log(RadiusLog.Dbg, pad + "  attr = " + vp.Name);
			Log(RadiusLog.Dbg, pad + "  tag = " + vp.Tag);
			Log(RadiusLog.Dbg, pad + "  op = " + vp.Op);
			Log(RadiusLog.Dbg, pad + "  pw_type = " + vp.DataType);
			if (vp.IsXlatTemplate)
				Log(RadiusLog.Dbg, pad + "  (xlat template)");
			Log(RadiusLog.Dbg, pad + "  value = " + vp.FormatValueForLog());
		}
	}

	/// <summary>Forwards a message to the native radlog callback.</summary>
	/// <param name="lvl"><see cref="RadiusLog"/> level.</param>
	/// <param name="msg">UTF-8 message text.</param>
	void Log(int lvl, string msg)
	{
		_radlog?.Invoke(lvl, msg);
	}
}

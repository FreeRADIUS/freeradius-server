namespace FreeRadius.Interop;

/// <summary>
/// Optional asynchronous policy API for I/O-bound work (HTTP, databases, LDAP, etc.).
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface <b>in addition to</b> <see cref="IRadiusPolicy"/> on the same class
/// (or implement only async methods and rely on default sync stubs — not recommended).
/// When the policy instance implements <see cref="IAsyncRadiusPolicy"/>, the interop layer
/// prefers async dispatch for all sections.
/// </para>
/// <para>
/// <b>Important:</b> native <c>rlm_dotnet</c> still blocks the RADIUS worker thread until
/// your <see cref="ValueTask"/> completes. The runtime uses
/// <c>ConfigureAwait(false).GetAwaiter().GetResult()</c>. Long-running work should use
/// timeouts (<c>async_timeout_ms</c> in radiusd.conf) and avoid blocking the thread pool.
/// </para>
/// <para>
/// Return <see cref="RadiusReply"/> to choose pair-list text or an <c>RDr1</c> binary blob
/// (<see cref="RadiusReplyFormat.ReplyBlobV1"/>). Use <see cref="RadiusReplyBlob.Encode"/>
/// to build blobs from <see cref="RadiusVp"/> instances.
/// </para>
/// <para>
/// For no-op section handlers, return <see cref="EmptyResult"/> or
/// <c>new ValueTask&lt;...&gt;(EmptyResult)</c>.
/// </para>
/// </remarks>
/// <seealso cref="IRadiusPolicy"/>
/// <seealso cref="RadiusReply"/>
public interface IAsyncRadiusPolicy
{
	/// <summary>
	/// <see cref="RlmRcode.Ok"/> with <see cref="RadiusReply.Empty"/> (no reply changes).
	/// </summary>
	static readonly (int Rcode, RadiusReply Reply) EmptyResult = (RlmRcode.Ok, RadiusReply.Empty);

	/// <summary>
	/// Asynchronous <c>authorize</c> handler.
	/// </summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Honored when <c>async_timeout_ms</c> is configured; otherwise only explicit cancellation applies.</param>
	/// <returns>Module result code and structured reply (pair-list or blob).</returns>
	ValueTask<(int Rcode, RadiusReply Reply)> AuthorizeAsync(RadiusRequest request, CancellationToken cancellationToken = default);

	/// <summary>Asynchronous <c>authenticate</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	/// <remarks>Default implementation delegates to <see cref="AuthorizeAsync"/>.</remarks>
	ValueTask<(int Rcode, RadiusReply Reply)> AuthenticateAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		AuthorizeAsync(request, cancellationToken);

	/// <summary>Asynchronous <c>preacct</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	/// <remarks>Default implementation delegates to <see cref="AccountingAsync"/>.</remarks>
	ValueTask<(int Rcode, RadiusReply Reply)> PreacctAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		AccountingAsync(request, cancellationToken);

	/// <summary>Asynchronous <c>accounting</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	/// <remarks>Default implementation returns <see cref="RlmRcode.Ok"/> with an empty pair-list reply.</remarks>
	ValueTask<(int Rcode, RadiusReply Reply)> AccountingAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		new(EmptyResult);

	/// <summary>Asynchronous <c>session</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	ValueTask<(int Rcode, RadiusReply Reply)> SessionAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		new(EmptyResult);

	/// <summary>Asynchronous <c>pre_proxy</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	ValueTask<(int Rcode, RadiusReply Reply)> PreProxyAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		new(EmptyResult);

	/// <summary>Asynchronous <c>post_proxy</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	ValueTask<(int Rcode, RadiusReply Reply)> PostProxyAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		new(EmptyResult);

	/// <summary>Asynchronous <c>post_auth</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	ValueTask<(int Rcode, RadiusReply Reply)> PostAuthAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		new(EmptyResult);

	/// <summary>Asynchronous <c>recv_coa</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	ValueTask<(int Rcode, RadiusReply Reply)> RecvCoaAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		new(EmptyResult);

	/// <summary>Asynchronous <c>send_coa</c> handler.</summary>
	/// <param name="request">Decoded request snapshot.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Module result code and structured reply.</returns>
	ValueTask<(int Rcode, RadiusReply Reply)> SendCoaAsync(RadiusRequest request, CancellationToken cancellationToken = default) =>
		new(EmptyResult);
}

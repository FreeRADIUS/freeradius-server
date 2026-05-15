namespace FreeRadius.Interop;

/// <summary>
/// FreeRADIUS module return codes (<c>rlm_rcode_t</c> in <c>src/include/modules.h</c> / <c>radiusd.h</c>).
/// </summary>
/// <remarks>
/// <para>
/// These integer constants must stay numerically identical to the C enum. The unlang
/// interpreter uses them to decide whether to continue, reject, or fail a request.
/// </para>
/// <para>
/// Typical policy outcomes:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="Ok"/> — success; continue processing.</description></item>
/// <item><description><see cref="Reject"/> — reject the user/request.</description></item>
/// <item><description><see cref="Fail"/> — module failure (also used when managed code throws).</description></item>
/// <item><description><see cref="Updated"/> — request was updated; often paired with reply attributes.</description></item>
/// <item><description><see cref="Notfound"/> — no matching entry (continue to next module).</description></item>
/// </list>
/// </remarks>
public static class RlmRcode
{
	/// <summary><c>RLM_MODULE_REJECT</c> (0) — reject the request.</summary>
	public const int Reject = 0;

	/// <summary><c>RLM_MODULE_FAIL</c> (1) — hard failure; usually logged as error.</summary>
	public const int Fail = 1;

	/// <summary><c>RLM_MODULE_OK</c> (2) — success.</summary>
	public const int Ok = 2;

	/// <summary><c>RLM_MODULE_HANDLED</c> (3) — module handled the request; stop section processing.</summary>
	public const int Handled = 3;

	/// <summary><c>RLM_MODULE_INVALID</c> (4) — invalid request/data.</summary>
	public const int Invalid = 4;

	/// <summary><c>RLM_MODULE_USERLOCK</c> (5) — user locked out.</summary>
	public const int Userlock = 5;

	/// <summary><c>RLM_MODULE_NOTFOUND</c> (6) — no match; try next module.</summary>
	public const int Notfound = 6;

	/// <summary><c>RLM_MODULE_NOOP</c> (7) — no operation performed.</summary>
	public const int Noop = 7;

	/// <summary><c>RLM_MODULE_UPDATED</c> (8) — attributes were updated.</summary>
	public const int Updated = 8;
}

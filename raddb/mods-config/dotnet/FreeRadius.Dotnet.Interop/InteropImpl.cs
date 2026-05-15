using System;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace FreeRadius.Interop;

/// <summary>
/// GCHandle target when <c>policy_instance_mode = per_thread</c>: factory state used to create
/// one <see cref="IRadiusPolicy"/> per RADIUS worker via <see cref="InteropImpl.EnsureThreadPolicyCore"/>.
/// </summary>
internal sealed class FactoryHolder
{
	/// <summary>CLR type from boot JSON <c>policy_type</c>.</summary>
	public required Type PolicyType { get; init; }

	/// <summary>Module instance name from boot JSON.</summary>
	public required string InstanceName { get; init; }

	/// <summary><c>extra_config</c> object from radiusd.conf.</summary>
	public required JsonElement Extra { get; init; }

	/// <summary>Native radlog wrapper, or <c>null</c> if unavailable.</summary>
	public Action<int, string>? Radlog { get; init; }

	/// <summary>Async policy timeout from <c>async_timeout_ms</c> (0 = none).</summary>
	public int AsyncTimeoutMs { get; init; }

	/// <summary>Keeps the published <see cref="NativeExports.AuthorizeBlobDelegate"/> alive.</summary>
	public GCHandle AuthorizeThunkPin { get; init; }
}

/// <summary>
/// GCHandle target for a loaded policy instance (shared mode or per-thread child).
/// </summary>
internal sealed class PolicyHolder
{
	/// <summary>Policy instance invoked for each request.</summary>
	public required IRadiusPolicy Policy { get; init; }

	/// <summary>Native radlog wrapper.</summary>
	public Action<int, string>? Radlog { get; init; }

	/// <summary>Thunk pin (shared mode only; per-thread children use default).</summary>
	public GCHandle AuthorizeThunkPin { get; init; }

	/// <summary>Async timeout passed to <see cref="IAsyncRadiusPolicy"/> calls.</summary>
	public int AsyncTimeoutMs { get; init; }
}

/// <summary>
/// Core interop logic: boot JSON, policy construction, request dispatch, reply encoding.
/// </summary>
/// <remarks>
/// <para>
/// Called only from <see cref="NativeExports"/> static methods (<see cref="NativeExports.TypeName"/>).
/// Policy assemblies should not reference this type; use <see cref="IRadiusPolicy"/> instead.
/// </para>
/// </remarks>
internal static class InteropImpl
{
	/// <summary>Loads policy type, publishes authorize thunk, allocates shared or factory handle.</summary>
	/// <inheritdoc cref="NativeExports.Instantiate"/>
	internal static int InstantiateCore(IntPtr configJsonUtf8, IntPtr outHandleAddr)
	{
		try
		{
			string? json = Marshal.PtrToStringUTF8(configJsonUtf8);
			if (string.IsNullOrEmpty(json)) return -1;

			BootJson? boot = JsonSerializer.Deserialize<BootJson>(json, InteropJson.JsonOpts);
			if (boot is null || string.IsNullOrEmpty(boot.PolicyType)) return -1;

			Action<int, string>? radlog = WrapNativeRadlog(ParseHexPtr(boot.RadlogFn));
			bool perThread = string.Equals(boot.PolicyInstanceMode, "per_thread", StringComparison.OrdinalIgnoreCase);

			Type policyType = Type.GetType(boot.PolicyType, throwOnError: true)!;
			if (policyType.IsAbstract || !typeof(IRadiusPolicy).IsAssignableFrom(policyType))
				return -1;

			if (string.IsNullOrEmpty(boot.PublishAuthorizeFn) ||
			    string.IsNullOrEmpty(boot.AuthorizeFnOut) ||
			    !TryPublishAuthorizeBlobFn(boot.AuthorizeFnOut, boot.PublishAuthorizeFn, radlog, out GCHandle authorizeThunkPin))
				return -1;

			object holder;
			if (perThread)
			{
				holder = new FactoryHolder
				{
					PolicyType = policyType,
					InstanceName = boot.InstanceName,
					Extra = boot.Extra,
					Radlog = radlog,
					AsyncTimeoutMs = boot.AsyncTimeoutMs,
					AuthorizeThunkPin = authorizeThunkPin
				};
			}
			else
			{
				IRadiusPolicy policy = CreatePolicy(policyType, radlog, boot.InstanceName, boot.Extra);
				holder = new PolicyHolder
				{
					Policy = policy,
					Radlog = radlog,
					AuthorizeThunkPin = authorizeThunkPin,
					AsyncTimeoutMs = boot.AsyncTimeoutMs
				};
			}

			GCHandle gch = GCHandle.Alloc(holder);
			Marshal.WriteIntPtr(outHandleAddr, GCHandle.ToIntPtr(gch));

			radlog?.Invoke(RadiusLog.Info,
				perThread
					? "*** dotnet instantiate (per-thread policy factory) ***"
					: "*** dotnet instantiate (shared policy) ***");
			radlog?.Invoke(RadiusLog.Dbg, json);
			return 0;
		}
		catch (Exception ex)
		{
			TryRadlogFromBootJson(configJsonUtf8, RadiusLog.Err,
				"dotnet InstantiateCore failed: " + ex.Message);
			return -1;
		}
	}

	/// <summary>Creates a per-thread policy <see cref="GCHandle"/> from a <see cref="FactoryHolder"/>.</summary>
	internal static int EnsureThreadPolicyCore(IntPtr factoryHandle, IntPtr outPolicyHandleAddr)
	{
		try
		{
			if (factoryHandle == IntPtr.Zero || outPolicyHandleAddr == IntPtr.Zero) return -1;

			if (GCHandle.FromIntPtr(factoryHandle).Target is not FactoryHolder factory)
				return -1;

			IRadiusPolicy policy = CreatePolicy(factory.PolicyType, factory.Radlog, factory.InstanceName, factory.Extra);
			PolicyHolder holder = new PolicyHolder
			{
				Policy = policy,
				Radlog = factory.Radlog,
				AuthorizeThunkPin = default,
				AsyncTimeoutMs = factory.AsyncTimeoutMs
			};
			GCHandle gch = GCHandle.Alloc(holder);
			Marshal.WriteIntPtr(outPolicyHandleAddr, GCHandle.ToIntPtr(gch));
			return 0;
		}
		catch (Exception ex)
		{
			TryRadlogFromHandle(factoryHandle, RadiusLog.Err,
				"dotnet EnsureThreadPolicyCore failed: " + ex.Message);
			return -1;
		}
	}

	/// <summary>Frees GCHandle, authorize delegate pin, and disposes <see cref="IDisposable"/> policies.</summary>
	/// <inheritdoc cref="NativeExports.Detach"/>
	internal static void DetachCore(IntPtr handle)
	{
		if (handle == IntPtr.Zero) return;

		GCHandle gch;
		try
		{
			gch = GCHandle.FromIntPtr(handle);
		}
		catch
		{
			return;
		}

		switch (gch.Target)
		{
			case PolicyHolder policyHolder:
				if (policyHolder.AuthorizeThunkPin.IsAllocated) policyHolder.AuthorizeThunkPin.Free();
				if (policyHolder.Policy is IDisposable d) d.Dispose();
				break;
			case FactoryHolder factoryHolder:
				if (factoryHolder.AuthorizeThunkPin.IsAllocated) factoryHolder.AuthorizeThunkPin.Free();
				break;
		}

		if (gch.IsAllocated) gch.Free();
	}

	/// <summary>Decodes request blob, dispatches to policy, writes reply and optional error JSON.</summary>
	/// <inheritdoc cref="NativeExports.AuthorizeBlobBridge.AuthorizeBlob"/>
	internal static int AuthorizeCore(IntPtr handle, IntPtr requestBlob, int requestLen, IntPtr replyBuf, int replyBufLen,
		IntPtr outWrittenPtr, IntPtr outReplyFormatPtr, IntPtr errorBuf, int errorBufLen, IntPtr outErrorWrittenPtr)
	{
		PolicyHolder? holder = null;

		if (handle == IntPtr.Zero || replyBuf == IntPtr.Zero || outWrittenPtr == IntPtr.Zero)
			return FailWithError(errorBuf, errorBufLen, outErrorWrittenPtr, "invalid_args",
				"AuthorizeCore: null handle, reply buffer, or out_written");

		if (requestBlob == IntPtr.Zero || requestLen <= 0)
			return FailWithError(errorBuf, errorBufLen, outErrorWrittenPtr, "invalid_args",
				"AuthorizeCore: empty request blob");

		Marshal.WriteInt32(outWrittenPtr, 0);
		if (outReplyFormatPtr != IntPtr.Zero) Marshal.WriteInt32(outReplyFormatPtr, 0);
		if (outErrorWrittenPtr != IntPtr.Zero) Marshal.WriteInt32(outErrorWrittenPtr, 0);

		try
		{
			switch (GCHandle.FromIntPtr(handle).Target)
			{
				case PolicyHolder ph:
					holder = ph;
					break;
				case FactoryHolder:
					return FailWithError(errorBuf, errorBufLen, outErrorWrittenPtr, "invalid_handle",
						"AuthorizeCore: per-thread factory handle passed; native must call EnsureThreadPolicy first");
				default:
					return FailWithError(errorBuf, errorBufLen, outErrorWrittenPtr, "invalid_handle",
						"AuthorizeCore: GCHandle target is not a policy Holder");
			}
		}
		catch (Exception ex)
		{
			return FailWithError(errorBuf, errorBufLen, outErrorWrittenPtr, ex.GetType().Name, ex.Message, ex.StackTrace);
		}

		try
		{
			byte[] reqBytes = new byte[requestLen];
			Marshal.Copy(requestBlob, reqBytes, 0, requestLen);

			RadiusRequest req;
			try
			{
				req = RadiusRequestBlob.Parse(reqBytes);
			}
			catch (Exception ex)
			{
				holder.Radlog?.Invoke(RadiusLog.Err, "dotnet InteropImpl: request blob parse failed: " + ex.Message);
				int show = Math.Min(requestLen, 64);
				if (show > 0)
					holder.Radlog?.Invoke(RadiusLog.Dbg, "dotnet InteropImpl: request blob prefix (hex): " +
								 Convert.ToHexString(reqBytes.AsSpan(0, show)));
				return FailWithError(errorBuf, errorBufLen, outErrorWrittenPtr, "blob_parse", ex.Message, ex.StackTrace);
			}

			(int rcode, RadiusReply reply) = DispatchBySection(holder.Policy, req, holder.AsyncTimeoutMs);
			WriteReply(reply, replyBuf, replyBufLen, outWrittenPtr, outReplyFormatPtr);
			return rcode;
		}
		catch (Exception ex)
		{
			holder.Radlog?.Invoke(RadiusLog.Err, "dotnet InteropImpl AuthorizeCore: " + ex);
			Marshal.WriteInt32(outWrittenPtr, 0);
			if (outReplyFormatPtr != IntPtr.Zero) Marshal.WriteInt32(outReplyFormatPtr, 0);
			return FailWithError(errorBuf, errorBufLen, outErrorWrittenPtr, ex.GetType().Name, ex.Message, ex.StackTrace);
		}
	}

	/// <summary>Copies <see cref="RadiusReply"/> into native buffers and sets format / length out-parameters.</summary>
	private static void WriteReply(RadiusReply reply, IntPtr replyBuf, int replyBufLen,
		IntPtr outWrittenPtr, IntPtr outReplyFormatPtr)
	{
		if (reply.Format == RadiusReplyFormat.ReplyBlobV1)
		{
			byte[] blob = reply.Blob ?? Array.Empty<byte>();
			int n = Math.Min(blob.Length, Math.Max(0, replyBufLen));
			if (n > 0) Marshal.Copy(blob, 0, replyBuf, n);
			Marshal.WriteInt32(outWrittenPtr, n);
			if (outReplyFormatPtr != IntPtr.Zero)
				Marshal.WriteInt32(outReplyFormatPtr, (int)RadiusReplyFormat.ReplyBlobV1);
			return;
		}

		byte[] bytes = Encoding.UTF8.GetBytes(reply.PairList ?? "");
		int max = Math.Max(0, replyBufLen - 1);
		int len = Math.Min(bytes.Length, max);
		if (len > 0) Marshal.Copy(bytes, 0, replyBuf, len);
		Marshal.WriteByte(replyBuf, len, 0);
		Marshal.WriteInt32(outWrittenPtr, len);
		if (outReplyFormatPtr != IntPtr.Zero)
			Marshal.WriteInt32(outReplyFormatPtr, (int)RadiusReplyFormat.PairListString);
	}

	/// <summary>Writes structured JSON via <see cref="InteropError"/> and returns <see cref="RlmRcode.Fail"/>.</summary>
	private static int FailWithError(IntPtr errorBuf, int errorBufLen, IntPtr outErrorWrittenPtr,
		string category, string message, string? stack = null)
	{
		InteropError.WriteToBuffer(errorBuf, errorBufLen, outErrorWrittenPtr, category, message, stack);
		return RlmRcode.Fail;
	}

	private static void TryRadlogFromBootJson(IntPtr configJsonUtf8, int lvl, string msg)
	{
		try
		{
			string? json = Marshal.PtrToStringUTF8(configJsonUtf8);
			if (string.IsNullOrEmpty(json)) return;
			BootJson? boot = JsonSerializer.Deserialize<BootJson>(json, InteropJson.JsonOpts);
			Action<int, string>? radlog = WrapNativeRadlog(ParseHexPtr(boot?.RadlogFn));
			radlog?.Invoke(lvl, msg);
		}
		catch
		{
			/* best effort */
		}
	}

	private static void TryRadlogFromHandle(IntPtr handle, int lvl, string msg)
	{
		try
		{
			object? target = GCHandle.FromIntPtr(handle).Target;
			Action<int, string>? radlog = target switch
			{
				FactoryHolder f => f.Radlog,
				PolicyHolder p => p.Radlog,
				_ => null
			};
			radlog?.Invoke(lvl, msg);
		}
		catch
		{
			/* best effort */
		}
	}

	/// <summary>Routes to sync or async policy method based on <see cref="RadiusRequest.Section"/>.</summary>
	private static (int rcode, RadiusReply reply) DispatchBySection(IRadiusPolicy policy, RadiusRequest req, int asyncTimeoutMs)
	{
		string s = string.IsNullOrEmpty(req.Section) ? "authorize" : req.Section;

		if (policy is IAsyncRadiusPolicy asyncPolicy)
			return RunAsync(s, asyncPolicy, req, asyncTimeoutMs);

		return s switch
		{
			"authorize" => ToReply(policy.Authorize(req)),
			"authenticate" => ToReply(policy.Authenticate(req)),
			"preacct" => ToReply(policy.Preacct(req)),
			"accounting" => ToReply(policy.Accounting(req)),
			"session" => ToReply(policy.Session(req)),
			"pre_proxy" => ToReply(policy.PreProxy(req)),
			"post_proxy" => ToReply(policy.PostProxy(req)),
			"post_auth" => ToReply(policy.PostAuth(req)),
			"recv_coa" => ToReply(policy.RecvCoa(req)),
			"send_coa" => ToReply(policy.SendCoa(req)),
			_ => (RlmRcode.Ok, RadiusReply.Empty)
		};
	}

	/// <summary>Blocking wait on <see cref="IAsyncRadiusPolicy"/> with optional <paramref name="asyncTimeoutMs"/>.</summary>
	private static (int rcode, RadiusReply reply) RunAsync(string section, IAsyncRadiusPolicy policy, RadiusRequest req, int asyncTimeoutMs)
	{
		using CancellationTokenSource cts = asyncTimeoutMs > 0 ? new CancellationTokenSource(asyncTimeoutMs) : new CancellationTokenSource();
		CancellationToken ct = cts.Token;

		ValueTask<(int Rcode, RadiusReply Reply)> task = section switch
		{
			"authorize" => policy.AuthorizeAsync(req, ct),
			"authenticate" => policy.AuthenticateAsync(req, ct),
			"preacct" => policy.PreacctAsync(req, ct),
			"accounting" => policy.AccountingAsync(req, ct),
			"session" => policy.SessionAsync(req, ct),
			"pre_proxy" => policy.PreProxyAsync(req, ct),
			"post_proxy" => policy.PostProxyAsync(req, ct),
			"post_auth" => policy.PostAuthAsync(req, ct),
			"recv_coa" => policy.RecvCoaAsync(req, ct),
			"send_coa" => policy.SendCoaAsync(req, ct),
			_ => new ValueTask<(int, RadiusReply)>((RlmRcode.Ok, RadiusReply.Empty))
		};

		try
		{
			return task.ConfigureAwait(false).GetAwaiter().GetResult();
		}
		catch (OperationCanceledException) when (asyncTimeoutMs > 0)
		{
			throw new TimeoutException($"policy async call exceeded {asyncTimeoutMs} ms (section {section})");
		}
	}

	private static (int rcode, RadiusReply reply) ToReply((int Rcode, string ReplyPairList) r)
	{
		if (r.ReplyPairList.Length == 0 || r.ReplyPairList == IRadiusPolicy.EmptyReply)
			return (r.Rcode, RadiusReply.Empty);
		return (r.Rcode, RadiusReply.FromPairList(r.ReplyPairList));
	}

	/// <summary>
	/// Instantiates policy via public ctor
	/// <c>(Action&lt;int,string&gt;, string, JsonElement)</c>,
	/// <c>(Action&lt;int,string&gt;, string)</c>, parameterless, or <c>Activator.CreateInstance</c>.
	/// </summary>
	/// <remarks>
	/// Dependency-injection container integration (e.g. <c>IServiceProvider</c>, custom factory types)
	/// is not implemented yet; add constructor resolution here if policies need injected services.
	/// </remarks>
	private static IRadiusPolicy CreatePolicy(Type policyType, Action<int, string>? radlog, string instanceName, JsonElement extra)
	{
		foreach (ConstructorInfo ctor in policyType.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
		{
			ParameterInfo[] p = ctor.GetParameters();
			if (p.Length == 3 &&
			    p[0].ParameterType == typeof(Action<int, string>) &&
			    p[1].ParameterType == typeof(string) &&
			    p[2].ParameterType == typeof(JsonElement))
				return (IRadiusPolicy)ctor.Invoke(new object?[] { radlog, instanceName, extra })!;

			if (p.Length == 2 &&
			    p[0].ParameterType == typeof(Action<int, string>) &&
			    p[1].ParameterType == typeof(string))
				return (IRadiusPolicy)ctor.Invoke(new object?[] { radlog, instanceName })!;

			if (p.Length == 0) return (IRadiusPolicy)ctor.Invoke(null)!;
		}

		return (IRadiusPolicy)Activator.CreateInstance(policyType)!;
	}

	/// <summary>Publishes <see cref="NativeExports.AuthorizeBlobBridge.AuthorizeBlob"/> to the native function pointer slot.</summary>
	private static unsafe bool TryPublishAuthorizeBlobFn(string authorizeFnOutHex, string publishAuthorizeFnHex,
							    Action<int, string>? radlog, out GCHandle authorizeThunkPin)
	{
		authorizeThunkPin = default;

		IntPtr slot = ParseHexPtr(authorizeFnOutHex);
		IntPtr publishFn = ParseHexPtr(publishAuthorizeFnHex);
		if (slot == IntPtr.Zero || publishFn == IntPtr.Zero)
		{
			radlog?.Invoke(RadiusLog.Err,
				$"dotnet: authorize_fn_out or publish_authorize_fn is missing or invalid (slot=0x{slot.ToInt64():x}, publishFn=0x{publishFn.ToInt64():x})");
			return false;
		}

		try
		{
			Type? nested = typeof(NativeExports).GetNestedType("AuthorizeBlobBridge", BindingFlags.Public);
			if (nested is null)
			{
				radlog?.Invoke(RadiusLog.Err, "dotnet: NativeExports.AuthorizeBlobBridge type not found");
				return false;
			}

			MethodInfo? m = nested.GetMethod("AuthorizeBlob", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
			if (m is null)
			{
				radlog?.Invoke(RadiusLog.Err, "dotnet: AuthorizeBlobBridge.AuthorizeBlob not found");
				return false;
			}

			NativeExports.AuthorizeBlobDelegate del = (NativeExports.AuthorizeBlobDelegate)Delegate.CreateDelegate(typeof(NativeExports.AuthorizeBlobDelegate), m);
			IntPtr fp = Marshal.GetFunctionPointerForDelegate(del);
			if (fp == IntPtr.Zero)
			{
				radlog?.Invoke(RadiusLog.Err, "dotnet: GetFunctionPointerForDelegate(AuthorizeBlob) returned zero");
				return false;
			}

			delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> publish = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void>)publishFn;

			radlog?.Invoke(RadiusLog.Dbg,
				$"dotnet: invoking publish_authorize_fn=0x{publishFn.ToInt64():x} slot=0x{slot.ToInt64():x} fp=0x{fp.ToInt64():x}");

			publish(slot, fp);

			IntPtr stored = Marshal.ReadIntPtr(slot);
			if (stored != fp)
			{
				radlog?.Invoke(RadiusLog.Err,
					$"dotnet: publish_authorize_fn did not store thunk (slot=0x{slot.ToInt64():x} got=0x{stored.ToInt64():x} expected=0x{fp.ToInt64():x})");
				return false;
			}

			authorizeThunkPin = GCHandle.Alloc(del);
			return true;
		}
		catch (Exception ex)
		{
			radlog?.Invoke(RadiusLog.Err, "dotnet: publishing AuthorizeBlob function pointer failed: " + ex);
			return false;
		}
	}

	private static IntPtr ParseHexPtr(string? s)
	{
		if (string.IsNullOrWhiteSpace(s)) return IntPtr.Zero;
		string t = s.Trim();
		if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) t = t[2..];
		ulong v = ulong.Parse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
		unchecked
		{
			return (IntPtr)(nint)v;
		}
	}

	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	private delegate void NativeRadlogDelegate(int lvl, IntPtr utf8Msg);

	private static Action<int, string>? WrapNativeRadlog(IntPtr fn)
	{
		if (fn == IntPtr.Zero) return null;
		NativeRadlogDelegate del = Marshal.GetDelegateForFunctionPointer<NativeRadlogDelegate>(fn);
		return (lvl, msg) =>
		{
			IntPtr p = Marshal.StringToCoTaskMemUTF8(msg);
			try
			{
				del(lvl, p);
			}
			finally
			{
				Marshal.FreeCoTaskMem(p);
			}
		};
	}

	/// <summary>Boot JSON schema built by <c>rlm_dotnet</c> at module instantiate time.</summary>
	private sealed class BootJson
	{
		/// <summary>Module instance name (<c>cf_section_name2</c>).</summary>
		[JsonPropertyName("instance_name")]
		public string InstanceName { get; set; } = "";

		/// <summary>CLR type name for the policy class.</summary>
		[JsonPropertyName("policy_type")]
		public string PolicyType { get; set; } = "";

		/// <summary><c>shared</c> or <c>per_thread</c>.</summary>
		[JsonPropertyName("policy_instance_mode")]
		public string PolicyInstanceMode { get; set; } = "shared";

		/// <summary>Milliseconds; 0 disables async cancellation timeout.</summary>
		[JsonPropertyName("async_timeout_ms")]
		public int AsyncTimeoutMs { get; set; }

		/// <summary>Hex pointer to native <c>radlog</c> function.</summary>
		[JsonPropertyName("radlog_fn")]
		public string RadlogFn { get; set; } = "";

		/// <summary>Hex pointer to <c>dotnet_publish_authorize_fn</c>.</summary>
		[JsonPropertyName("publish_authorize_fn")]
		public string PublishAuthorizeFn { get; set; } = "";

		/// <summary>Hex pointer to slot storing the authorize thunk.</summary>
		[JsonPropertyName("authorize_fn_out")]
		public string AuthorizeFnOut { get; set; } = "";

		/// <summary>Parsed <c>extra_config</c> from radiusd.conf.</summary>
		[JsonPropertyName("extra")]
		public JsonElement Extra { get; set; }
	}
}

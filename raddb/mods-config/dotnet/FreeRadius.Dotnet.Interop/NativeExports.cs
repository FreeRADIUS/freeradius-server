using System.Runtime.InteropServices;

namespace FreeRadius.Interop;

/// <summary>
/// Unmanaged function pointers resolved by .NET hostfxr
/// (<c>load_assembly_and_get_function_pointer</c>) from <c>rlm_dotnet</c>.
/// </summary>
/// <remarks>
/// <para>
/// Configure <c>native_exports_type</c> in radiusd.conf to <see cref="TypeName"/>.
/// </para>
/// <para>
/// Policy authors typically do not call these methods directly; implement
/// <see cref="IRadiusPolicy"/> in a separate assembly. These entrypoints exist so the
/// native module can bootstrap the CLR and publish the authorize thunk.
/// </para>
/// <para>
/// Delegate type names for hostfxr use the DNNE form:
/// <c>Namespace.Type+MethodDelegate, AssemblyName</c> (see each nested delegate).
/// </para>
/// </remarks>
public static class NativeExports
{
	/// <summary>
	/// Value for <c>native_exports_type</c> in <c>mods-available/dotnet</c> (hostfxr type name).
	/// </summary>
	public const string TypeName = "FreeRadius.Interop.NativeExports, FreeRadius.Dotnet.Interop";

	/// <summary>
	/// FreeRADIUS module that loads this assembly (same as <see cref="SdkOverview.ModuleName"/>).
	/// </summary>
	public const string ModuleName = SdkOverview.ModuleName;

	/// <summary>Supported <c>RDb1</c> request blob format version (wire protocol v1).</summary>
	public const ushort RequestBlobFormatVersion = RadiusRequestBlob.FormatVersion;

	/// <summary>Supported <c>RDr1</c> reply blob format version (wire protocol v1).</summary>
	public const ushort ReplyBlobFormatVersion = RadiusReplyBlob.FormatVersion;

	/// <summary>
	/// Bootstraps the policy: deserializes boot JSON, loads <c>policy_type</c>, publishes
	/// <see cref="AuthorizeBlobDelegate"/>, returns a <see cref="System.Runtime.InteropServices.GCHandle"/> as <c>outHandle</c>.
	/// </summary>
	/// <param name="configJsonUtf8">NUL-terminated UTF-8 JSON (instance name, policy type, radlog pointer, etc.).</param>
	/// <param name="outHandleAddr">Pointer to <c>void*</c> receiving the managed handle.</param>
	/// <returns>0 on success, -1 on failure.</returns>
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	public delegate int InstantiateDelegate(IntPtr configJsonUtf8, IntPtr outHandleAddr);

	/// <summary>
	/// Tears down a handle from <see cref="InstantiateDelegate"/> (frees GCHandle, disposes <see cref="IDisposable"/> policies).
	/// </summary>
	/// <param name="handle">Handle pointer from instantiate.</param>
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	public delegate void DetachDelegate(IntPtr handle);

	/// <summary>
	/// Creates a per-thread <see cref="IRadiusPolicy"/> when <c>policy_instance_mode = per_thread</c>.
	/// </summary>
	/// <param name="factoryHandle"><see cref="FactoryHolder"/> GCHandle from instantiate.</param>
	/// <param name="outPolicyHandleAddr">Pointer to <c>void*</c> receiving per-thread policy handle.</param>
	/// <returns>0 on success, -1 on failure.</returns>
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	public delegate int EnsureThreadPolicyDelegate(IntPtr factoryHandle, IntPtr outPolicyHandleAddr);

	/// <summary>
	/// Per-request entry: decode <c>RDb1</c> blob, run policy, write reply (pair-list or <c>RDr1</c>).
	/// </summary>
	/// <param name="handle">Policy or per-thread policy GCHandle.</param>
	/// <param name="requestBlob">Pointer to <c>RDb1</c> bytes.</param>
	/// <param name="requestLen">Length of request blob.</param>
	/// <param name="replyBuf">Output buffer for reply string or binary blob.</param>
	/// <param name="replyBufLen">Capacity of <paramref name="replyBuf"/>.</param>
	/// <param name="outWrittenPtr">Pointer to <c>int</c> bytes written to reply buffer.</param>
	/// <param name="outReplyFormatPtr">Pointer to <c>int</c> <see cref="RadiusReplyFormat"/> value, or zero if unused.</param>
	/// <param name="errorBuf">Optional buffer for JSON error on <see cref="RlmRcode.Fail"/>.</param>
	/// <param name="errorBufLen">Capacity of <paramref name="errorBuf"/>.</param>
	/// <param name="outErrorWrittenPtr">Pointer to <c>int</c> error JSON bytes written.</param>
	/// <returns><see cref="RlmRcode"/> result for the request.</returns>
	[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
	public delegate int AuthorizeBlobDelegate(IntPtr handle, IntPtr requestBlob, int requestLen, IntPtr replyBuf, int replyBufLen,
		IntPtr outWrittenPtr, IntPtr outReplyFormatPtr, IntPtr errorBuf, int errorBufLen, IntPtr outErrorWrittenPtr);

	/// <summary>
	/// Indirection type used when publishing the authorize function pointer to native code.
	/// </summary>
	/// <remarks>
	/// <see cref="InteropImpl"/> reflects <see cref="AuthorizeBlobBridge.AuthorizeBlob"/> and passes
	/// <c>Marshal.GetFunctionPointerForDelegate</c> to the native
	/// <c>publish_authorize_fn</c> slot from boot JSON.
	/// </remarks>
	public sealed class AuthorizeBlobBridge
	{
		/// <summary>Prevents external instantiation.</summary>
		private AuthorizeBlobBridge()
		{
		}

		/// <summary>Thunk invoked by native code; forwards to <see cref="InteropImpl.AuthorizeCore"/>.</summary>
		/// <inheritdoc cref="AuthorizeBlobDelegate"/>
		public static int AuthorizeBlob(IntPtr handle, IntPtr requestBlob, int requestLen, IntPtr replyBuf, int replyBufLen,
			IntPtr outWrittenPtr, IntPtr outReplyFormatPtr, IntPtr errorBuf, int errorBufLen, IntPtr outErrorWrittenPtr) =>
			InteropImpl.AuthorizeCore(handle, requestBlob, requestLen, replyBuf, replyBufLen, outWrittenPtr,
				outReplyFormatPtr, errorBuf, errorBufLen, outErrorWrittenPtr);
	}

	/// <summary>hostfxr export: module load / policy bootstrap.</summary>
	/// <inheritdoc cref="InstantiateDelegate"/>
	public static int Instantiate(IntPtr configJsonUtf8, IntPtr outHandleAddr) =>
		InteropImpl.InstantiateCore(configJsonUtf8, outHandleAddr);

	/// <summary>hostfxr export: module unload / cleanup.</summary>
	/// <inheritdoc cref="DetachDelegate"/>
	public static void Detach(IntPtr handle) => InteropImpl.DetachCore(handle);

	/// <summary>hostfxr export: per-thread policy creation.</summary>
	/// <inheritdoc cref="EnsureThreadPolicyDelegate"/>
	public static int EnsureThreadPolicy(IntPtr factoryHandle, IntPtr outPolicyHandleAddr) =>
		InteropImpl.EnsureThreadPolicyCore(factoryHandle, outPolicyHandleAddr);
}

using System;
using System.Text;
using System.Text.Json;

namespace FreeRadius.Interop;

/// <summary>
/// Serializes structured failure metadata into the native error buffer when managed code
/// returns <see cref="RlmRcode.Fail"/>.
/// </summary>
/// <remarks>
/// <para>
/// JSON shape: <c>{"category":"...","message":"...","stack":"..."}</c>. The native module
/// logs this when <c>error_buffer_size</c> is non-zero and the policy returns failure.
/// </para>
/// <para>
/// Policy authors normally do not call this type; throw exceptions or return
/// <see cref="RlmRcode.Fail"/> from handlers and let <see cref="InteropImpl"/> populate the buffer.
/// </para>
/// </remarks>
internal static class InteropError
{
	/// <summary>
	/// Writes UTF-8 JSON to <paramref name="errorBuf"/> and sets <paramref name="outErrorWrittenPtr"/>.
	/// </summary>
	/// <param name="errorBuf">Native buffer from <c>rlm_dotnet</c>.</param>
	/// <param name="errorBufLen">Capacity in bytes.</param>
	/// <param name="outErrorWrittenPtr">Pointer to <c>int</c> receiving bytes written (excluding NUL).</param>
	/// <param name="category">Short machine-oriented category (e.g. <c>blob_parse</c>, exception type name).</param>
	/// <param name="message">Human-readable detail.</param>
	/// <param name="stack">Optional stack trace; empty string if <c>null</c>.</param>
	public static void WriteToBuffer(IntPtr errorBuf, int errorBufLen, IntPtr outErrorWrittenPtr, string category, string message, string? stack)
	{
		if (outErrorWrittenPtr != IntPtr.Zero)
			System.Runtime.InteropServices.Marshal.WriteInt32(outErrorWrittenPtr, 0);
		if (errorBuf == IntPtr.Zero || errorBufLen <= 0 || outErrorWrittenPtr == IntPtr.Zero) return;

		string json = JsonSerializer.Serialize(new
		{
			category,
			message,
			stack = stack ?? ""
		}, InteropJson.JsonOpts);

		byte[] bytes = Encoding.UTF8.GetBytes(json);
		int max = Math.Max(0, errorBufLen - 1);
		int n = Math.Min(bytes.Length, max);
		if (n > 0) System.Runtime.InteropServices.Marshal.Copy(bytes, 0, errorBuf, n);
		System.Runtime.InteropServices.Marshal.WriteByte(errorBuf, n, 0);
		System.Runtime.InteropServices.Marshal.WriteInt32(outErrorWrittenPtr, n);
	}
}

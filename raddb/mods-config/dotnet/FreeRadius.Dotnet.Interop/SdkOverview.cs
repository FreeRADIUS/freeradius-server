[assembly: System.Reflection.AssemblyMetadata("FreeRADIUS.Module", "rlm_dotnet")]

namespace FreeRadius.Interop;

/// <summary>
/// <para>
/// <b>FreeRadius.Dotnet.Interop</b> is the managed SDK used with FreeRADIUS
/// <c>rlm_dotnet</c>. Publish this assembly (and its <c>.runtimeconfig.json</c>)
/// to <c>${modconfdir}/dotnet/publish/Release/</c>, point <c>mods-available/dotnet</c>
/// at it, and implement <see cref="IRadiusPolicy"/> (or <see cref="IAsyncRadiusPolicy"/>)
/// in your own DLL.
/// </para>
/// <para>
/// <b>Request path:</b> native code serializes the current RADIUS request into a
/// binary <c>RDb1</c> v1 blob (<see cref="RadiusRequestBlob"/>). The interop layer
/// decodes it to <see cref="RadiusRequest"/> and dispatches to your policy method
/// for the active virtual-server section (<c>authorize</c>, <c>authenticate</c>,
/// <c>accounting</c>, …).
/// </para>
/// <para>
/// <b>Reply path:</b> return an <see cref="RlmRcode"/> and either a FreeRADIUS
/// pair-list string (e.g. <c>Reply-Message := "ok"</c>) or a binary <c>RDr1</c> blob
/// built with <see cref="RadiusReplyBlob"/>. Async policies return
/// <see cref="RadiusReply"/> directly.
/// </para>
/// <para>
/// <b>Logging:</b> use the <c>Action&lt;int, string&gt;</c> radlog delegate passed to
/// your policy constructor and levels from <see cref="RadiusLog"/> (same numeric values
/// as FreeRADIUS <c>log_type_t</c>).
/// </para>
/// <para>
/// See <c>src/modules/rlm_dotnet/README.md</c> and <see cref="ExamplePolicy"/>.
/// </para>
/// </summary>
/// <remarks>
/// This type exists to host assembly-level documentation in the generated XML file.
/// Policy authors implement <see cref="IRadiusPolicy"/> rather than calling members here.
/// </remarks>
public static class SdkOverview
{
	/// <summary>Interop assembly label (informational; not the FreeRADIUS server version).</summary>
	public const string SdkName = "FreeRadius.Dotnet.Interop";

	/// <summary>FreeRADIUS module name (<c>rlm_dotnet</c>) that loads this SDK.</summary>
	public const string ModuleName = "rlm_dotnet";

	/// <summary>
	/// Version of <see cref="SdkName"/> from the assembly manifest (diagnostics / logging).
	/// </summary>
	/// <remarks>Not the FreeRADIUS server version. Set via <c>Version</c> in the interop <c>.csproj</c> if needed.</remarks>
	public static readonly Version SdkVersion =
		typeof(SdkOverview).Assembly.GetName().Version!;
}

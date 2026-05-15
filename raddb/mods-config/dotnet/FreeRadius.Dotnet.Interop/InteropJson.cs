using System.Text.Json;

namespace FreeRadius.Interop;

/// <summary>
/// Shared <see cref="JsonSerializerOptions"/> for boot JSON and error payloads.
/// </summary>
/// <remarks>
/// <para>
/// Kept in a separate type from <see cref="NativeExports"/> so policy assemblies that reference
/// only <see cref="IRadiusPolicy"/> types are less likely to trigger eager JIT of hostfxr export
/// entrypoints during assembly load.
/// </para>
/// <para>
/// Options are intentionally minimal: case-sensitive property names, compact output (no indentation).
/// </para>
/// </remarks>
internal static class InteropJson
{
	/// <summary>Serializer options used for boot JSON deserialization and error JSON serialization.</summary>
	public static readonly JsonSerializerOptions JsonOpts = new()
	{
		PropertyNameCaseInsensitive = false,
		WriteIndented = false
	};
}

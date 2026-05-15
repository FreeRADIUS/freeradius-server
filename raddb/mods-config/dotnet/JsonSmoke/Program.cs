namespace JsonSmoke;

/// <summary>
/// Standalone smoke test runner for <see cref="RadiusRequestBlobParseTests"/>.
/// </summary>
/// <remarks>
/// Run from the repository:
/// <code>dotnet run -c Release --project raddb/mods-config/dotnet/JsonSmoke/JsonSmoke.csproj</code>
/// For NUnit: <c>dotnet test raddb/mods-config/dotnet/JsonSmoke.Tests/JsonSmoke.Tests.csproj</c>
/// </remarks>
public static class Program
{
	/// <summary>Entry point; exits 0 on success, throws on failure.</summary>
	public static int Main()
	{
		Console.WriteLine("RadiusRequestBlob.Parse tests:");
		RadiusRequestBlobParseTests.RunAll();
		Console.WriteLine("All tests passed.");
		return 0;
	}
}

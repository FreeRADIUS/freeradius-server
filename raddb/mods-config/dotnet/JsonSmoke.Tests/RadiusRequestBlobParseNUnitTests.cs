using NUnit.Framework;

namespace JsonSmoke.Tests;

/// <summary>
/// NUnit wrapper around shared <see cref="JsonSmoke.RadiusRequestBlobParseTests"/> logic.
/// </summary>
[TestFixture]
public sealed class RadiusRequestBlobParseNUnitTests
{
	/// <summary>Runs the full positive and negative parse test suite.</summary>
	[Test]
	public void RunAll_ParseTests()
	{
		JsonSmoke.RadiusRequestBlobParseTests.RunAll();
	}
}

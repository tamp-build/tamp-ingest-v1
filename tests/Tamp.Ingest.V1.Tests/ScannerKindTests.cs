using Xunit;

namespace Tamp.Ingest.V1.Tests;

public class ScannerKindTests
{
    [Theory]
    [InlineData(ScannerKind.Unknown,    "unknown")]
    [InlineData(ScannerKind.OpenGrep,   "opengrep")]
    [InlineData(ScannerKind.TruffleHog, "trufflehog")]
    [InlineData(ScannerKind.CodeQL,     "codeql")]
    [InlineData(ScannerKind.Trivy,      "trivy")]
    [InlineData(ScannerKind.Grype,      "grype")]
    [InlineData(ScannerKind.Syft,       "syft")]
    [InlineData(ScannerKind.Roslyn,     "roslyn")]
    [InlineData(ScannerKind.ReSharper,  "resharper")]
    [InlineData(ScannerKind.ESLint,     "eslint")]
    [InlineData(ScannerKind.AxeCore,    "axe-core")]  // hyphenated, special-cased
    public void ToWire_MapsEveryEnumMember(ScannerKind kind, string expected)
        => Assert.Equal(expected, kind.ToWire());

    [Fact]
    public void ToWire_CoversEveryDeclaredEnumValue()
    {
        // Tripwire — every ScannerKind must map. New value forgotten in the switch → test fails.
        foreach (ScannerKind kind in Enum.GetValues<ScannerKind>())
        {
            var wire = kind.ToWire();
            Assert.False(string.IsNullOrWhiteSpace(wire), $"ScannerKind.{kind} produced empty wire value.");
            Assert.Equal(wire, wire.ToLowerInvariant());
        }
    }
}

public class SeverityTests
{
    [Theory]
    [InlineData(Severity.Info,     "info")]
    [InlineData(Severity.Low,      "low")]
    [InlineData(Severity.Medium,   "medium")]
    [InlineData(Severity.High,     "high")]
    [InlineData(Severity.Critical, "critical")]
    public void ToWire_MapsEveryEnumMember(Severity severity, string expected)
        => Assert.Equal(expected, severity.ToWire());

    [Fact]
    public void OrderingIsAscendingBySeverity()
    {
        // Sinks rely on numeric comparison to bucket severities — guard the ordering.
        Assert.True(Severity.Info < Severity.Low);
        Assert.True(Severity.Low < Severity.Medium);
        Assert.True(Severity.Medium < Severity.High);
        Assert.True(Severity.High < Severity.Critical);
    }
}

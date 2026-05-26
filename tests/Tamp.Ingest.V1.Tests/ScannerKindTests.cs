using Xunit;

namespace Tamp.Ingest.V1.Tests;

public class ScannerKindTests
{
    [Theory]
    [InlineData(ScannerKind.Unknown,           "unknown")]
    [InlineData(ScannerKind.OpenGrep,          "opengrep")]
    [InlineData(ScannerKind.TruffleHog,        "trufflehog")]
    [InlineData(ScannerKind.CodeQL,            "codeql")]
    [InlineData(ScannerKind.Trivy,             "trivy")]
    [InlineData(ScannerKind.Checkov,           "checkov")]
    [InlineData(ScannerKind.Tfsec,             "tfsec")]
    [InlineData(ScannerKind.Kics,              "kics")]
    [InlineData(ScannerKind.Zap,               "zap")]
    [InlineData(ScannerKind.Spectral,          "spectral")]
    [InlineData(ScannerKind.Oasdiff,           "oasdiff")]
    [InlineData(ScannerKind.Cosign,            "cosign")]
    [InlineData(ScannerKind.NetArchTest,       "netarchtest")]
    [InlineData(ScannerKind.DependencyCruiser, "dependency-cruiser")]
    [InlineData(ScannerKind.Stryker,           "stryker")]
    [InlineData(ScannerKind.Coverlet,          "coverlet")]
    [InlineData(ScannerKind.OsvScanner,        "osv-scanner")]
    [InlineData(ScannerKind.Grype,             "grype")]
    [InlineData(ScannerKind.Syft,              "syft")]
    [InlineData(ScannerKind.Roslyn,            "roslyn")]
    [InlineData(ScannerKind.ReSharper,         "resharper")]
    [InlineData(ScannerKind.ESLint,            "eslint")]
    [InlineData(ScannerKind.AxeCore,           "axe-core")]   // hyphenated
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

    [Fact]
    public void EnumMatchesSpec_v1_1_CanonicalSet()
    {
        // Spec §3.1 v1.1 vocabulary — sink-side authoritative list. Drift here is a
        // contract change worth a 0.x bump on this satellite + TAM-NNN against the spec.
        var expected = new[]
        {
            "unknown", "opengrep", "trufflehog", "codeql", "trivy",
            "checkov", "tfsec", "kics", "zap", "spectral", "oasdiff",
            "cosign", "netarchtest", "dependency-cruiser", "stryker", "coverlet",
            "osv-scanner", "roslyn", "syft", "grype", "resharper", "eslint", "axe-core",
        };

        var actual = Enum.GetValues<ScannerKind>().Select(k => k.ToWire()).OrderBy(s => s, StringComparer.Ordinal).ToArray();
        var want   = expected.OrderBy(s => s, StringComparer.Ordinal).ToArray();
        Assert.Equal(want, actual);
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

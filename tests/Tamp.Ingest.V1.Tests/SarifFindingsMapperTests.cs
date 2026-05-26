using Tamp.Sarif;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

public class SarifFindingsMapperTests
{
    private static IngestHierarchy SampleHierarchy() => new()
    {
        Client = "BrewingCoder",
        Project = "tamp",
        Component = "tamp",
        Version = "1.13.0",
    };

    [Fact]
    public void FromSarif_EmptyLog_ReturnsEmpty()
    {
        var log = new SarifLog { Runs = Array.Empty<SarifRun>() };
        Assert.Empty(SarifFindingsMapper.FromSarif(log));
    }

    [Theory]
    [InlineData(SarifLevel.Error,   Severity.High)]
    [InlineData(SarifLevel.Warning, Severity.Medium)]
    [InlineData(SarifLevel.Note,    Severity.Low)]
    [InlineData(SarifLevel.None,    Severity.Info)]
    public void FromSarif_MapsSarifLevelToSeverity(SarifLevel level, Severity expected)
    {
        var log = new SarifLog
        {
            Runs = new[]
            {
                new SarifRun
                {
                    Results = new[]
                    {
                        new SarifResult { RuleId = "X1", Level = level, Message = new SarifMessage { Text = "test" } },
                    },
                },
            },
        };

        var f = Assert.Single(SarifFindingsMapper.FromSarif(log));
        Assert.Equal(expected, f.Severity);
    }

    [Fact]
    public void FromSarif_ExtractsFilePathAndLineFromPhysicalLocation()
    {
        var log = new SarifLog
        {
            Runs = new[]
            {
                new SarifRun
                {
                    Results = new[]
                    {
                        new SarifResult
                        {
                            RuleId = "S125", Level = SarifLevel.Note,
                            Message = new SarifMessage { Text = "Remove commented-out code." },
                            Locations = new[]
                            {
                                new SarifLocation
                                {
                                    PhysicalLocation = new SarifPhysicalLocation
                                    {
                                        ArtifactLocation = new SarifArtifactLocation { Uri = "src/Foo.cs" },
                                        Region = new SarifRegion { StartLine = 42 },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        };

        var f = Assert.Single(SarifFindingsMapper.FromSarif(log));
        Assert.Equal("S125", f.RuleId);
        Assert.Equal("src/Foo.cs", f.FilePath);
        Assert.Equal(42, f.Line);
        Assert.Equal("Remove commented-out code.", f.Title);
    }

    [Fact]
    public void FromSarif_TitleTrimsToFirstLineAnd512Chars()
    {
        var bigMessage = new string('x', 600) + "\nsecond line";
        var log = new SarifLog
        {
            Runs = new[]
            {
                new SarifRun
                {
                    Results = new[]
                    {
                        new SarifResult { RuleId = "X1", Level = SarifLevel.Warning, Message = new SarifMessage { Text = bigMessage } },
                    },
                },
            },
        };

        var f = Assert.Single(SarifFindingsMapper.FromSarif(log));
        Assert.Equal(512, f.Title.Length);
        Assert.DoesNotContain('\n', f.Title);
        // Description preserves the full message (no length cap on the wire).
        Assert.Equal(bigMessage, f.Description);
    }

    [Fact]
    public void FromSarif_NullRuleId_FallsBackToPlaceholder()
    {
        var log = new SarifLog
        {
            Runs = new[]
            {
                new SarifRun { Results = new[] { new SarifResult { RuleId = null, Level = SarifLevel.Warning, Message = new SarifMessage { Text = "no rule id" } } } },
            },
        };

        var f = Assert.Single(SarifFindingsMapper.FromSarif(log));
        Assert.Equal("<unknown>", f.RuleId);
    }

    [Fact]
    public void FromSarif_NullMessage_GetsPlaceholderTitle()
    {
        var log = new SarifLog
        {
            Runs = new[]
            {
                new SarifRun { Results = new[] { new SarifResult { RuleId = "X1", Level = SarifLevel.Warning, Message = new SarifMessage { Text = null } } } },
            },
        };

        var f = Assert.Single(SarifFindingsMapper.FromSarif(log));
        Assert.Equal("<no message>", f.Title);
    }

    [Fact]
    public void FromSarif_DefaultSubCategory_AppliesToAllFindings()
    {
        var log = new SarifLog
        {
            Runs = new[]
            {
                new SarifRun
                {
                    Results = new[]
                    {
                        new SarifResult { RuleId = "wcag-1.1.1", Level = SarifLevel.Warning, Message = new SarifMessage { Text = "Image without alt text" } },
                        new SarifResult { RuleId = "wcag-1.4.3", Level = SarifLevel.Warning, Message = new SarifMessage { Text = "Low contrast" } },
                    },
                },
            },
        };

        var findings = SarifFindingsMapper.FromSarif(log, defaultSubCategory: "accessibility");

        Assert.Equal(2, findings.Count);
        Assert.All(findings, f => Assert.Equal("accessibility", f.SubCategory));
    }

    [Fact]
    public void FromSarif_MultipleRuns_FlattenInOrder()
    {
        var log = new SarifLog
        {
            Runs = new[]
            {
                new SarifRun { Results = new[] { new SarifResult { RuleId = "A", Level = SarifLevel.Error,   Message = new SarifMessage { Text = "a" } } } },
                new SarifRun { Results = new[] { new SarifResult { RuleId = "B", Level = SarifLevel.Warning, Message = new SarifMessage { Text = "b" } } } },
                new SarifRun { Results = new[] { new SarifResult { RuleId = "C", Level = SarifLevel.Note,    Message = new SarifMessage { Text = "c" } } } },
            },
        };

        var findings = SarifFindingsMapper.FromSarif(log);
        Assert.Equal(new[] { "A", "B", "C" }, findings.Select(f => f.RuleId).ToArray());
    }

    [Fact]
    public void BuildRequest_CarriesHierarchyAndScanner()
    {
        var hierarchy = SampleHierarchy() with { Flavor = "net10", Branch = "main" };
        var log = new SarifLog { Runs = Array.Empty<SarifRun>() };

        var req = SarifFindingsMapper.BuildRequest(hierarchy, ScannerKind.Roslyn, log);

        Assert.Equal("BrewingCoder", req.Client);
        Assert.Equal("net10", req.Flavor);
        Assert.Equal("main", req.Branch);
        Assert.Equal(ScannerKind.Roslyn, req.Scanner);
        Assert.Empty(req.Findings);
    }

    [Fact]
    public void BuildRequest_NullArgsThrow()
    {
        var log = new SarifLog();
        Assert.Throws<ArgumentNullException>(() => SarifFindingsMapper.BuildRequest(null!, ScannerKind.Roslyn, log));
        Assert.Throws<ArgumentNullException>(() => SarifFindingsMapper.BuildRequest(SampleHierarchy(), ScannerKind.Roslyn, null!));
    }
}

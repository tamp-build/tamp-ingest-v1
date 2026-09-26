using System.Text.Json;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// Round-trip every golden fixture from <c>tamp-findings/tests/Fixtures/Ingest/v1/</c>:
/// deserialize the fixture into the V1 typed DTO, re-serialize via
/// <see cref="IngestJsonOptions.Default"/>, and assert structural equality with the
/// original JSON. Catches shape drift, casing-policy regressions, and any field the
/// typed DTO silently drops on deserialize.
/// </summary>
/// <remarks>
/// Pattern: deserialize → re-serialize → JsonElement compare (structural, order-tolerant).
/// Per spec v1.2 §6: if a fixture disagrees with the spec text, the fixture wins.
/// </remarks>
public class FixtureRoundTripTests
{
    private static string FixturePath(string name)
        => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static string ReadFixture(string name) => File.ReadAllText(FixturePath(name));

    [Fact]
    public void Fixture_01_Sbom_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("01-sbom-request.json");
        var req = JsonSerializer.Deserialize<SbomIngestRequest>(original, IngestJsonOptions.Default)!;

        // Sanity asserts on the parsed shape.
        Assert.Equal("BrewingCoder", req.Client);
        Assert.Equal("tamp.findings", req.Project);
        Assert.Equal("solution", req.ComponentKind);
        Assert.Equal("net10", req.Flavor);
        Assert.Equal("syft", req.ToolName);
        Assert.NotNull(req.MetadataTools);
        Assert.Single(req.MetadataTools!);
        Assert.Equal(2, req.Components.Count);
        Assert.Single(req.Dependencies);
        Assert.Equal("pkg:nuget/Microsoft.EntityFrameworkCore@10.0.8", req.Components[0].Purl);
        Assert.NotNull(req.Components[0].Hashes);
        Assert.Equal("deadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00d",
                     req.Components[0].Hashes!["SHA-256"]);

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_02_FindingsRoslyn_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("02-findings-roslyn-request.json");
        var req = JsonSerializer.Deserialize<FindingsIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal(ScannerKind.Roslyn, req.Scanner);
        Assert.Equal(2, req.Findings.Count);
        Assert.Equal("S125", req.Findings[0].RuleId);
        Assert.Equal(Severity.Low, req.Findings[0].Severity);
        Assert.Equal(5, req.Findings[0].Line);

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_03_FindingsEslint_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("03-findings-eslint-request.json");
        var req = JsonSerializer.Deserialize<FindingsIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal(ScannerKind.ESLint, req.Scanner);
        Assert.Equal("web", req.Flavor);   // eslint scoped to web flavor

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_04_FindingsTrivy_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("04-findings-trivy-request.json");
        var req = JsonSerializer.Deserialize<FindingsIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal(ScannerKind.Trivy, req.Scanner);
        // SubCategory bucketing — Trivy emits multiple per findings array.
        var subCats = req.Findings.Select(f => f.SubCategory).ToHashSet();
        Assert.Contains("misconfiguration", subCats);
        Assert.Contains("secret", subCats);

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_05_CoverageDotnet_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("05-coverage-dotnet-request.json");
        var req = JsonSerializer.Deserialize<CoverageIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal("OpenCover", req.ToolName);
        Assert.Equal(12.5m, req.SequenceCoverage);
        Assert.Equal(9.8m, req.BranchCoverage);
        Assert.Single(req.Modules);
        Assert.Single(req.Modules[0].Classes);
        Assert.Equal(13, req.Modules[0].Classes[0].VisitedLines.Count);
        Assert.NotNull(req.SourceFiles);
        Assert.Single(req.SourceFiles!);

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_06_CoverageVitest_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("06-coverage-vitest-request.json");
        var req = JsonSerializer.Deserialize<CoverageIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal("vitest@coverage-v8", req.ToolName);
        Assert.Null(req.BranchCoverage);                  // vitest doesn't report branches
        Assert.Equal("web", req.Flavor);
        Assert.NotNull(req.SourceFiles);
        Assert.Empty(req.SourceFiles!);                   // empty array — must round-trip

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_07_TestResults_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("07-test-results-request.json");
        var req = JsonSerializer.Deserialize<TestResultsIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal("VSTest", req.ToolName);
        Assert.Equal(56, req.TotalCount);
        Assert.Equal(1, req.FailedCount);
        Assert.Equal(2, req.Suites.Count);
        Assert.Equal(TestOutcome.Failed, req.Suites[1].Cases[0].Outcome);
        Assert.NotNull(req.Suites[1].Cases[0].ErrorMessage);

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_08_ScanRuns_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("08-scan-runs-request.json");
        var req = JsonSerializer.Deserialize<ScanRunsIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal(4, req.Receipts.Count);
        Assert.Equal(ScanRunStatus.Succeeded, req.Receipts[0].Status);
        Assert.Equal(ScanRunStatus.Failed, req.Receipts[3].Status);
        Assert.Contains("Killed externally", req.Receipts[3].Notes ?? "");

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_09_SbomVulnerabilitiesUpsert_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("09-sbom-vulnerabilities-upsert-request.json");
        var req = JsonSerializer.Deserialize<SbomVulnerabilitiesUpsertRequest>(original, IngestJsonOptions.Default)!;

        Assert.Equal(Guid.Parse("11111111-2222-3333-4444-555555555555"), req.SnapshotId);
        Assert.Equal(2, req.Vulnerabilities.Count);
        Assert.Equal("CVE-2024-0001", req.Vulnerabilities[0].AdvisoryId);
        Assert.Equal(Severity.High, req.Vulnerabilities[0].Severity);
        Assert.Null(req.Vulnerabilities[1].ReferenceUrl);   // null fields round-trip

        AssertStructurallyEqual(original, req);
    }

    [Fact]
    public void Fixture_10_SbomProvenanceSlsa_PassesThroughVerbatim()
    {
        // Provenance bodies are opaque to V1 — we don't deserialize them. The fixture exists
        // to document the shape the sink stores verbatim, NOT to round-trip a typed model.
        // This test just asserts the fixture file is well-formed JSON of the expected shape.
        var original = ReadFixture("10-sbom-provenance-slsa-request.json");
        using var doc = JsonDocument.Parse(original);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        Assert.True(doc.RootElement.TryGetProperty("_type", out var type));
        Assert.Equal("https://in-toto.io/Statement/v1", type.GetString());
        Assert.True(doc.RootElement.TryGetProperty("predicateType", out var predicateType));
        Assert.Equal("https://slsa.dev/provenance/v1", predicateType.GetString());
    }

    [Fact]
    public void Fixture_11_SbomProvenanceDsse_PassesThroughVerbatim()
    {
        var original = ReadFixture("11-sbom-provenance-dsse-request.json");
        using var doc = JsonDocument.Parse(original);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        // DSSE envelopes carry payloadType + payload + signatures[]; sink keys off payloadType.
        Assert.True(doc.RootElement.TryGetProperty("payloadType", out _));
    }

    [Fact]
    public void Fixture_12_TestResultsWithActor_DeserializesAndReserializesStructurally()
    {
        var original = ReadFixture("12-test-results-with-actor-request.json");
        var req = JsonSerializer.Deserialize<TestResultsIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.NotNull(req.Actor);
        Assert.Equal("pool/3", req.Actor!.Id);
        Assert.Equal(ActorKind.Agent, req.Actor.Kind);

        AssertStructurallyEqual(original, req);   // v1.3 actor block round-trips with no drift
    }

    /// <summary>
    /// Re-serialize <paramref name="reserialized"/> via the canonical options and
    /// assert it structurally equals <paramref name="originalJson"/> (key sets +
    /// values match, modulo property ordering).
    /// </summary>
    private static void AssertStructurallyEqual<T>(string originalJson, T reserialized)
    {
        var reserializedJson = JsonSerializer.Serialize(reserialized, IngestJsonOptions.Default);
        using var origDoc = JsonDocument.Parse(originalJson);
        using var reserDoc = JsonDocument.Parse(reserializedJson);
        AssertJsonElementsEqual(origDoc.RootElement, reserDoc.RootElement, path: "$");
    }

    private static void AssertJsonElementsEqual(JsonElement a, JsonElement b, string path)
    {
        if (a.ValueKind != b.ValueKind)
        {
            throw new Xunit.Sdk.XunitException($"ValueKind mismatch at {path}: {a.ValueKind} vs {b.ValueKind}\nleft:  {a}\nright: {b}");
        }
        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                // Fixtures document optional fields by spelling them out as explicit nulls
                // (e.g. "buildId": null). Our wire shape drops nulls on serialize — both
                // are valid per the spec. Compare on the non-null intersection.
                var aProps = a.EnumerateObject()
                              .Where(p => p.Value.ValueKind != JsonValueKind.Null)
                              .ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);
                var bProps = b.EnumerateObject()
                              .Where(p => p.Value.ValueKind != JsonValueKind.Null)
                              .ToDictionary(p => p.Name, p => p.Value, StringComparer.Ordinal);

                // Reserialize must include every NON-null original property — flag any missing.
                foreach (var k in aProps.Keys)
                {
                    if (!bProps.ContainsKey(k))
                        throw new Xunit.Sdk.XunitException($"Reserialize dropped property '{k}' at {path}");
                }
                // Reserialize must not invent properties not in the original.
                foreach (var k in bProps.Keys)
                {
                    if (!aProps.ContainsKey(k))
                        throw new Xunit.Sdk.XunitException($"Reserialize added unexpected property '{k}' at {path}");
                }
                foreach (var (k, v) in aProps)
                {
                    AssertJsonElementsEqual(v, bProps[k], $"{path}.{k}");
                }
                break;

            case JsonValueKind.Array:
                var aItems = a.EnumerateArray().ToArray();
                var bItems = b.EnumerateArray().ToArray();
                if (aItems.Length != bItems.Length)
                    throw new Xunit.Sdk.XunitException($"Array length mismatch at {path}: {aItems.Length} vs {bItems.Length}");
                for (int i = 0; i < aItems.Length; i++)
                    AssertJsonElementsEqual(aItems[i], bItems[i], $"{path}[{i}]");
                break;

            case JsonValueKind.String:
                Assert.Equal(a.GetString(), b.GetString());
                break;

            case JsonValueKind.Number:
                // Compare raw text — `12.5` vs `12.5m` could differ in raw form but be numerically equal.
                // Test the parsed decimal value instead.
                Assert.Equal(a.GetDecimal(), b.GetDecimal());
                break;

            case JsonValueKind.True:
            case JsonValueKind.False:
                Assert.Equal(a.GetBoolean(), b.GetBoolean());
                break;

            case JsonValueKind.Null:
                Assert.Equal(JsonValueKind.Null, b.ValueKind);
                break;
        }
    }
}

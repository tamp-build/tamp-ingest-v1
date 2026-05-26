using System.Net;
using System.Text;
using System.Text.Json;
using Tamp;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// Wire-level tests for <see cref="TampIngestClient"/> 0.2.0. Asserts that:
/// the path is right, method is POST, auth header is set, body shape is flat-hierarchy,
/// no query params get emitted, enums serialize PascalCase.
/// </summary>
public class TampIngestClientTests
{
    private static readonly Uri BaseUri = new("https://sink.example.com/");
    private static readonly Secret Token = new("test-token", "cli_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    private static IngestHierarchy SampleHierarchy() => new()
    {
        Client = "BrewingCoder",
        Project = "tamp",
        Component = "tamp",
        ComponentKind = "solution",
        Flavor = "net10",
        Version = "0.2.0",
        CommitSha = "deadbeef",
        Branch = "main",
    };

    private static (TampIngestClient client, CapturingHandler handler) NewClient(
        Func<HttpRequestMessage, HttpResponseMessage>? responder = null)
    {
        var handler = new CapturingHandler();
        if (responder is not null) handler.Responder = responder;
        var http = new HttpClient(handler);
        var client = new TampIngestClient(BaseUri, Token, http);
        return (client, handler);
    }

    // ---------- Auth + base URI ----------

    [Fact]
    public async Task EveryRequest_StampsBearerAuthHeader()
    {
        var (client, handler) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        });

        await client.PostScanRunsAsync(new ScanRunsIngestRequest
        {
            Client = "BrewingCoder", Project = "tamp", Component = "tamp", Version = "1",
            Receipts = Array.Empty<ScanRunReceipt>(),
        });

        Assert.Equal("Bearer cli_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA", handler.Sent.Single().Authorization);
    }

    // ---------- /ingest/sbom — flat hierarchy in body, no query params ----------

    [Fact]
    public async Task PostSbom_PostsFlatHierarchyInBody_NoQueryParams()
    {
        var snapshotId = Guid.NewGuid();
        var componentVersionId = Guid.NewGuid();
        var (client, handler) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                $"{{\"componentVersionId\":\"{componentVersionId}\",\"sbomSnapshotId\":\"{snapshotId}\",\"componentsCount\":2,\"dependenciesCount\":1,\"vulnerabilitiesCount\":0}}",
                Encoding.UTF8, "application/json"),
        });

        var req = new SbomIngestRequest
        {
            Client = "BrewingCoder", Project = "tamp", Component = "tamp",
            ComponentKind = "solution", Flavor = "net10", Version = "1.13.0",
            Components = new[] { new SbomComponent { Purl = "pkg:nuget/Foo@1", Name = "Foo", Version = "1" } },
            Dependencies = Array.Empty<SbomDependency>(),
        };

        var resp = await client.PostSbomAsync(req);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/sbom", sent.Path);
        Assert.Empty(sent.Query);
        Assert.Equal("application/json", sent.ContentType);

        using var body = JsonDocument.Parse(sent.Body!);
        Assert.Equal("BrewingCoder", body.RootElement.GetProperty("client").GetString());
        Assert.Equal("tamp", body.RootElement.GetProperty("project").GetString());
        Assert.Equal("solution", body.RootElement.GetProperty("componentKind").GetString());
        Assert.Equal("net10", body.RootElement.GetProperty("flavor").GetString());

        Assert.Equal(snapshotId, resp.SbomSnapshotId);
        Assert.Equal(componentVersionId, resp.ComponentVersionId);
        Assert.Equal(2, resp.ComponentsCount);
    }

    // ---------- /ingest/findings — scanner enum in body, PascalCase ----------

    [Fact]
    public async Task PostFindings_PutsScannerInBody_AsPascalCaseString()
    {
        var (client, handler) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"componentVersionId\":\"00000000-0000-0000-0000-000000000000\",\"findingsInserted\":0,\"findingsUpdated\":0,\"findingsReopened\":0,\"findingsClosed\":0,\"findingsSuppressed\":0}",
                Encoding.UTF8, "application/json"),
        });

        var req = new FindingsIngestRequest
        {
            Client = "BrewingCoder", Project = "tamp", Component = "tamp", Version = "1",
            Scanner = ScannerKind.Roslyn,
            Findings = Array.Empty<IngestFinding>(),
        };

        await client.PostFindingsAsync(req);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/findings", sent.Path);
        Assert.Empty(sent.Query);
        using var body = JsonDocument.Parse(sent.Body!);
        Assert.Equal("Roslyn", body.RootElement.GetProperty("scanner").GetString());
    }

    [Fact]
    public async Task PostFindings_HyphenatedScanner_SerializesAsPascalCase()
    {
        var (client, handler) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"componentVersionId\":\"00000000-0000-0000-0000-000000000000\",\"findingsInserted\":0,\"findingsUpdated\":0,\"findingsReopened\":0,\"findingsClosed\":0,\"findingsSuppressed\":0}",
                Encoding.UTF8, "application/json"),
        });

        await client.PostFindingsAsync(new FindingsIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v",
            Scanner = ScannerKind.AxeCore,
            Findings = Array.Empty<IngestFinding>(),
        });

        var sent = Assert.Single(handler.Sent);
        using var body = JsonDocument.Parse(sent.Body!);
        // The wire shape for body enum names is PascalCase, NOT hyphenated.
        // (`ScannerKindExtensions.ToWire()` returns `"axe-core"` for the LEGACY 0.1.x URL form;
        // body-encoded enums use the bare PascalCase name.)
        Assert.Equal("AxeCore", body.RootElement.GetProperty("scanner").GetString());
    }

    // ---------- /ingest/sbom-snapshots/{id}/provenance — raw JSON body ----------

    [Fact]
    public async Task PostSbomProvenance_PostsRawJsonToSnapshotScopedPath()
    {
        var (client, handler) = NewClient();
        var snapshotId = Guid.NewGuid();
        var provenance = "{\"_type\":\"https://in-toto.io/Statement/v1\"}";

        await client.PostSbomProvenanceAsync(snapshotId, provenance);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal($"/ingest/sbom-snapshots/{snapshotId:D}/provenance", sent.Path);
        Assert.Empty(sent.Query);
        Assert.Equal(provenance, sent.Body);
    }

    [Fact]
    public async Task PostSbomProvenance_RejectsEmptyGuidAndEmptyBody()
    {
        var (client, _) = NewClient();
        await Assert.ThrowsAsync<ArgumentException>(() => client.PostSbomProvenanceAsync(Guid.Empty, "{}"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.PostSbomProvenanceAsync(Guid.NewGuid(), ""));
    }

    // ---------- /ingest/scan-runs — receipts[] + ScanRunStatus PascalCase ----------

    [Fact]
    public async Task PostScanRuns_SerializesReceiptsWithPascalCaseStatus()
    {
        var (client, handler) = NewClient();
        await client.PostScanRunsAsync(new ScanRunsIngestRequest
        {
            Client = "BrewingCoder", Project = "tamp", Component = "tamp", Version = "1",
            Receipts = new[]
            {
                new ScanRunReceipt
                {
                    Scanner = ScannerKind.Trivy,
                    Status = ScanRunStatus.Succeeded,
                    StartedAt = new DateTimeOffset(2026, 5, 26, 1, 0, 0, TimeSpan.Zero),
                    CompletedAt = new DateTimeOffset(2026, 5, 26, 1, 0, 42, TimeSpan.Zero),
                    FindingsCount = 3,
                    ToolName = "Trivy",
                    ToolVersion = "0.55.1",
                },
            },
        });

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/scan-runs", sent.Path);
        using var body = JsonDocument.Parse(sent.Body!);
        var receipt = body.RootElement.GetProperty("receipts")[0];
        Assert.Equal("Trivy", receipt.GetProperty("scanner").GetString());
        Assert.Equal("Succeeded", receipt.GetProperty("status").GetString());
        Assert.Equal("2026-05-26T01:00:00Z", receipt.GetProperty("startedAt").GetString());  // Z form, not +00:00
        Assert.Equal(3, receipt.GetProperty("findingsCount").GetInt32());
    }

    // ---------- /sbom-vulnerabilities/upsert — note: NO /ingest/ prefix ----------

    [Fact]
    public async Task PostSbomVulnerabilitiesUpsert_UsesUnprefixedPath_AndKeysOffSnapshotId()
    {
        var snapshotId = Guid.NewGuid();
        var (client, handler) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{{\"snapshotId\":\"{snapshotId}\",\"matched\":1,\"unmatched\":0,\"inserted\":1,\"updated\":0}}",
                Encoding.UTF8, "application/json"),
        });

        var resp = await client.PostSbomVulnerabilitiesUpsertAsync(new SbomVulnerabilitiesUpsertRequest
        {
            SnapshotId = snapshotId,
            Vulnerabilities = new[]
            {
                new SbomVulnerability
                {
                    PackageName = "Foo", PackageVersion = "1.0.0",
                    AdvisoryId = "CVE-2024-0001", Severity = Severity.High,
                },
            },
        });

        var sent = Assert.Single(handler.Sent);
        // Critical assertion: no /ingest/ prefix on this endpoint (spec v1.2 §2.7).
        Assert.Equal("/sbom-vulnerabilities/upsert", sent.Path);
        Assert.Empty(sent.Query);
        using var body = JsonDocument.Parse(sent.Body!);
        Assert.Equal(snapshotId.ToString(), body.RootElement.GetProperty("snapshotId").GetString());
        Assert.Equal("High", body.RootElement.GetProperty("vulnerabilities")[0].GetProperty("severity").GetString());

        Assert.Equal(1, resp.Inserted);
    }

    // ---------- Coverage + test-results ----------

    [Fact]
    public async Task PostCoverage_RouteAndDecimalSerialization()
    {
        var (client, handler) = NewClient();
        await client.PostCoverageAsync(new CoverageIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v",
            ToolName = "OpenCover",
            CompletedAt = new DateTimeOffset(2026, 5, 26, 0, 0, 0, TimeSpan.Zero),
            SequenceCoverage = 87.3m, BranchCoverage = 71.2m,
            CoveredSequences = 873, TotalSequences = 1000,
            Modules = Array.Empty<CoverageModule>(),
        });

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/coverage", sent.Path);
        using var body = JsonDocument.Parse(sent.Body!);
        Assert.Equal(87.3m, body.RootElement.GetProperty("sequenceCoverage").GetDecimal());
        Assert.Equal(71.2m, body.RootElement.GetProperty("branchCoverage").GetDecimal());
    }

    [Fact]
    public async Task PostTestResults_RouteAndCountsSerialization()
    {
        var (client, handler) = NewClient();
        await client.PostTestResultsAsync(new TestResultsIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v",
            ToolName = "VSTest",
            CompletedAt = new DateTimeOffset(2026, 5, 26, 0, 0, 0, TimeSpan.Zero),
            DurationMs = 14700,
            TotalCount = 56, PassedCount = 55, FailedCount = 1, SkippedCount = 0, InconclusiveCount = 0,
            Suites = Array.Empty<TestSuite>(),
        });

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/test-results", sent.Path);
        using var body = JsonDocument.Parse(sent.Body!);
        Assert.Equal(56, body.RootElement.GetProperty("totalCount").GetInt32());
        Assert.Equal(1, body.RootElement.GetProperty("failedCount").GetInt32());
    }

    // ---------- Error mapping ----------

    [Fact]
    public async Task NonSuccessResponse_ThrowsApiException_WithBodyCaptured()
    {
        var (client, _) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("{\"error\":\"client is required\"}", Encoding.UTF8, "application/json"),
        });

        var ex = await Assert.ThrowsAnyAsync<Tamp.Http.ApiException>(() => client.PostScanRunsAsync(new ScanRunsIngestRequest
        {
            Client = "BrewingCoder", Project = "tamp", Component = "tamp", Version = "1",
            Receipts = Array.Empty<ScanRunReceipt>(),
        }));

        Assert.Equal(HttpStatusCode.BadRequest, ex.StatusCode);
        Assert.Contains("client is required", ex.ResponseBody);
    }

    [Fact]
    public async Task NonSuccessResponse_OnProvenancePath_BubblesApiException()
    {
        var (client, _) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("{\"error\":\"snapshot not found\"}", Encoding.UTF8, "application/json"),
        });

        var ex = await Assert.ThrowsAnyAsync<Tamp.Http.ApiException>(() => client.PostSbomProvenanceAsync(Guid.NewGuid(), "{}"));
        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
        Assert.Contains("snapshot not found", ex.ResponseBody);
    }
}

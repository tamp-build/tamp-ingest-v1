using System.Net;
using System.Text;
using System.Text.Json;
using Tamp;
using Tamp.Sarif;
using Tamp.Sbom;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

public class TampIngestClientTests
{
    private static readonly Uri BaseUri = new("https://sink.example.com/");
    private static readonly Secret Token = new("test-token", "cli_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    private static IngestBuildContext SampleCtx() => new()
    {
        Client = "Tamp",
        Project = "tamp",
        Component = "tamp",
        Version = "1.13.0",
        Flavor = "net10",
        CommitSha = "deadbeefcafe",
        Branch = "main",
        BuildId = "17431",
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

    // ---------- Auth ----------

    [Fact]
    public async Task EveryRequest_StampsBearerAuthHeader()
    {
        var (client, handler) = NewClient();
        var ctx = SampleCtx();

        await client.PostCoverageAsync(ctx, new CoverageIngestRequestDto
        {
            Format = "cobertura",
            LinePercent = 80.0m,
        });

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("Bearer cli_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", sent.Authorization);
    }

    [Fact]
    public async Task BaseUri_TrailingSlashAgnostic()
    {
        // Run once with trailing slash, once without — both should hit the same endpoint.
        foreach (var b in new[] { "https://sink.example.com", "https://sink.example.com/" })
        {
            var handler = new CapturingHandler();
            using var http = new HttpClient(handler);
            using var client = new TampIngestClient(new Uri(b), Token, http);

            await client.PostCoverageAsync(SampleCtx(), new CoverageIngestRequestDto { Format = "cobertura", LinePercent = 50.0m });

            var sent = Assert.Single(handler.Sent);
            Assert.Equal("/ingest/coverage", sent.Path);
        }
    }

    // ---------- /ingest/sbom ----------

    [Fact]
    public async Task PostSbom_PostsCycloneDx_ToCorrectPath_WithHierarchyQuery_AndReturnsSnapshotId()
    {
        var snapshotId = Guid.NewGuid();
        var (client, handler) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{{\"snapshotId\":\"{snapshotId}\",\"created\":true}}",
                Encoding.UTF8, "application/json"),
        });

        var bom = new CycloneDxBom
        {
            SpecVersion = "1.5",
            SerialNumber = $"urn:uuid:{Guid.NewGuid()}",
            Version = 1,
        };

        var resp = await client.PostSbomAsync(SampleCtx(), bom);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal(HttpMethod.Post, sent.Method);
        Assert.Equal("/ingest/sbom", sent.Path);
        Assert.Contains("clientName=Tamp", sent.Query);
        Assert.Contains("componentName=tamp", sent.Query);
        Assert.Contains("versionString=1.13.0", sent.Query);
        Assert.Equal("application/json", sent.ContentType);
        Assert.Contains("\"specVersion\"", sent.Body); // SARIF/SBOM writer emits camelCase
        Assert.Equal(snapshotId, resp.SnapshotId);
        Assert.True(resp.Created);
    }

    [Fact]
    public async Task PostSbom_NullArguments_Throw()
    {
        var (client, _) = NewClient();
        var bom = new CycloneDxBom { SpecVersion = "1.5", SerialNumber = "urn:uuid:x", Version = 1 };

        await Assert.ThrowsAsync<ArgumentNullException>(() => client.PostSbomAsync(null!, bom));
        await Assert.ThrowsAsync<ArgumentNullException>(() => client.PostSbomAsync(SampleCtx(), null!));
    }

    // ---------- /ingest/sbom/{id}/provenance ----------

    [Fact]
    public async Task PostSbomProvenance_PostsRawJson_ToSnapshotScopedPath()
    {
        var (client, handler) = NewClient();
        var snapshotId = Guid.NewGuid();
        var provenance = "{\"_type\":\"https://in-toto.io/Statement/v0.1\"}";

        await client.PostSbomProvenanceAsync(snapshotId, provenance);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal(HttpMethod.Post, sent.Method);
        Assert.Equal($"/ingest/sbom/{snapshotId:D}/provenance", sent.Path);
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

    // ---------- /ingest/findings ----------

    [Fact]
    public async Task PostFindings_PostsSarif_WithScannerKindQueryParam()
    {
        var (client, handler) = NewClient();

        var log = new SarifLog
        {
            Version = "2.1.0",
            Schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            Runs = new[]
            {
                new SarifRun { Tool = new SarifTool { Driver = new SarifToolComponent { Name = "trufflehog", Version = "3.85.1" } } },
            },
        };

        await client.PostFindingsAsync(SampleCtx(), ScannerKind.TruffleHog, log);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/findings", sent.Path);
        Assert.Contains("scannerKind=trufflehog", sent.Query);
        Assert.Contains("clientName=Tamp", sent.Query);
        Assert.Equal("application/json", sent.ContentType);
        // SARIF preserves its case-sensitive wire shape (lowercase property names per spec).
        // SarifWriter uses WriteIndented + camelCase, so colons have a trailing space.
        Assert.Contains("\"version\": \"2.1.0\"", sent.Body);
        Assert.Contains("\"runs\"", sent.Body);
    }

    [Fact]
    public async Task PostFindings_UnknownScanner_StillSerializes()
    {
        var (client, handler) = NewClient();
        var log = new SarifLog
        {
            Version = "2.1.0",
            Schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            Runs = Array.Empty<SarifRun>(),
        };

        await client.PostFindingsAsync(SampleCtx(), ScannerKind.Unknown, log);

        var sent = Assert.Single(handler.Sent);
        Assert.Contains("scannerKind=unknown", sent.Query);
    }

    // ---------- /ingest/coverage ----------

    [Fact]
    public async Task PostCoverage_SerializesCamelCase_AndDropsNulls()
    {
        var (client, handler) = NewClient();
        var coverage = new CoverageIngestRequestDto
        {
            Format = "cobertura",
            LinePercent = 87.3m,
            BranchPercent = 71.2m,
            LinesCovered = 873,
            LinesTotal = 1000,
            // BranchesCovered / BranchesTotal / RawReportGzB64 intentionally null
        };

        await client.PostCoverageAsync(SampleCtx(), coverage);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/coverage", sent.Path);
        // camelCase property names from base client serializer
        Assert.Contains("\"format\":\"cobertura\"", sent.Body);
        Assert.Contains("\"linePercent\":87.3", sent.Body);
        Assert.Contains("\"branchPercent\":71.2", sent.Body);
        Assert.Contains("\"linesCovered\":873", sent.Body);
        // nulls dropped
        Assert.DoesNotContain("branchesCovered", sent.Body);
        Assert.DoesNotContain("rawReportGzB64", sent.Body);
    }

    // ---------- /ingest/test-results ----------

    [Fact]
    public async Task PostTestResults_PostsAggregateRollup()
    {
        var (client, handler) = NewClient();
        var results = new TestResultsIngestRequestDto
        {
            Format = "trx",
            Total = 412,
            Passed = 405,
            Failed = 3,
            Skipped = 4,
            DurationSeconds = 87.4m,
        };

        await client.PostTestResultsAsync(SampleCtx(), results);

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/test-results", sent.Path);
        Assert.Contains("\"total\":412", sent.Body);
        Assert.Contains("\"failed\":3", sent.Body);
        Assert.Contains("\"durationSeconds\":87.4", sent.Body);
    }

    // ---------- /ingest/scan-runs ----------

    [Fact]
    public async Task PostScanRuns_SerializesEnumsAsStrings()
    {
        var (client, handler) = NewClient();
        var receipt = new ScanRunReceipt
        {
            Scanner = ScannerKind.OpenGrep,
            StartedUtc = DateTimeOffset.UtcNow.AddSeconds(-30),
            CompletedUtc = DateTimeOffset.UtcNow,
            ExitCode = 1,
            FindingsTotal = 7,
            FindingsBySeverity = new Dictionary<string, int>
            {
                ["high"] = 2,
                ["medium"] = 5,
            },
            ScannerVersion = "opengrep 1.2.3",
        };

        await client.PostScanRunsAsync(SampleCtx(), new[] { receipt });

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/scan-runs", sent.Path);
        // Enum serialized as wire value (lowercased member name via JsonStringEnumConverter — base
        // client uses default which produces "OpenGrep"; the wire converter on IngestJsonContext maps
        // ScannerKind via its enum name. Either is sink-acceptable; we just want it as a string.)
        Assert.Contains("\"scanner\":", sent.Body);
        Assert.Contains("\"exitCode\":1", sent.Body);
        Assert.Contains("\"findingsTotal\":7", sent.Body);
        Assert.Contains("\"high\":2", sent.Body);
    }

    [Fact]
    public async Task PostScanRuns_EmptyCollection_IsNoOp()
    {
        var (client, handler) = NewClient();

        await client.PostScanRunsAsync(SampleCtx(), Array.Empty<ScanRunReceipt>());

        Assert.Empty(handler.Sent);
    }

    // ---------- /ingest/sbom-vulnerabilities ----------

    [Fact]
    public async Task PostSbomVulnerabilities_SerializesCvssAndPurl()
    {
        var (client, handler) = NewClient();
        var vuln = new SbomVulnerability
        {
            Id = "CVE-2024-12345",
            Purl = "pkg:nuget/Newtonsoft.Json@13.0.1",
            Severity = Severity.High,
            CvssScore = 7.5m,
            CvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            FixVersion = "13.0.3",
            AdvisoryUrl = "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
        };

        await client.PostSbomVulnerabilitiesAsync(SampleCtx(), new[] { vuln });

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/sbom-vulnerabilities", sent.Path);
        Assert.Contains("\"id\":\"CVE-2024-12345\"", sent.Body);
        Assert.Contains("\"purl\":\"pkg:nuget/Newtonsoft.Json@13.0.1\"", sent.Body);
        Assert.Contains("\"cvssScore\":7.5", sent.Body);
        Assert.Contains("\"fixVersion\":\"13.0.3\"", sent.Body);
    }

    [Fact]
    public async Task PostSbomVulnerabilities_EmptyCollection_IsNoOp()
    {
        var (client, handler) = NewClient();

        await client.PostSbomVulnerabilitiesAsync(SampleCtx(), Array.Empty<SbomVulnerability>());

        Assert.Empty(handler.Sent);
    }

    // ---------- Error mapping ----------

    [Fact]
    public async Task NonSuccessResponse_FromSarifPath_ThrowsApiException_WithBodyCaptured()
    {
        var (client, _) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("{\"error\":\"client scope mismatch\"}", Encoding.UTF8, "application/json"),
        });

        var log = new SarifLog
        {
            Version = "2.1.0",
            Schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            Runs = Array.Empty<SarifRun>(),
        };

        var ex = await Assert.ThrowsAnyAsync<Tamp.Http.ApiException>(
            () => client.PostFindingsAsync(SampleCtx(), ScannerKind.OpenGrep, log));

        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.Contains("client scope mismatch", ex.ResponseBody);
    }

    [Fact]
    public async Task NonSuccessResponse_FromCoveragePath_BubblesUpAsApiException()
    {
        var (client, _) = NewClient(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("{\"error\":\"missing format\"}", Encoding.UTF8, "application/json"),
        });

        var ex = await Assert.ThrowsAnyAsync<Tamp.Http.ApiException>(
            () => client.PostCoverageAsync(SampleCtx(), new CoverageIngestRequestDto
            {
                Format = "cobertura",
                LinePercent = 50.0m,
            }));

        Assert.Equal(HttpStatusCode.BadRequest, ex.StatusCode);
    }

    // ---------- Cancellation ----------

    [Fact]
    public async Task Cancellation_TokenPropagatesIntoTheRequest()
    {
        var handler = new CapturingHandler
        {
            Responder = _ => throw new OperationCanceledException(),
        };
        using var http = new HttpClient(handler);
        using var client = new TampIngestClient(BaseUri, Token, http);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // HttpClient wraps the cancellation in TaskCanceledException (subclass of OCE) — accept either.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.PostCoverageAsync(SampleCtx(), new CoverageIngestRequestDto { Format = "cobertura", LinePercent = 0m }, cts.Token));
    }
}

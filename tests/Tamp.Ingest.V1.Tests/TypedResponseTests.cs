using System.Net;
using System.Text;
using Tamp;
using Tamp.Http;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// TAM-293 (strata-home post-mortem). tamp.findings returns a body for every ingest, but the client used
/// to discard it, so a producer could log only what it SENT, never what was stored or which build it
/// landed on. These tests pin the typed responses, field for field, against the sink's own
/// <c>*IngestResponse</c> records (camelCase, as ASP.NET serializes them).
/// </summary>
public class TypedResponseTests
{
    private static readonly Uri BaseUri = new("https://sink.example.com/");
    private static readonly Secret Token = new("test-token", "prj_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    private static TampIngestClient NewClient(Func<HttpRequestMessage, HttpResponseMessage>? responder = null)
    {
        var handler = new CapturingHandler();
        if (responder is not null) handler.Responder = responder;
        return new TampIngestClient(BaseUri, Token, new HttpClient(handler));
    }

    private static HttpResponseMessage Ok(string json) =>
        new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    [Fact]
    public async Task PostCoverage_Returns_What_The_Sink_Stored()
    {
        var r = await NewClient().PostCoverageAsync(new CoverageIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v", ToolName = "OpenCover",
            CompletedAt = DateTimeOffset.UnixEpoch, SequenceCoverage = 1m, BranchCoverage = 1m,
            CoveredSequences = 1, TotalSequences = 1, Modules = Array.Empty<CoverageModule>(),
        });

        Assert.Equal(CapturingHandler.ComponentVersionId, r.ComponentVersionId);
        Assert.Equal(CapturingHandler.ReportId, r.CoverageReportId);
        Assert.Equal(3, r.ModulesCount);
        Assert.Equal(41, r.ClassesCount);
        Assert.Equal(17, r.SourceFilesCount);
    }

    [Fact]
    public async Task PostTestResults_Returns_What_The_Sink_Stored()
    {
        var r = await NewClient().PostTestResultsAsync(new TestResultsIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v", ToolName = "VSTest",
            CompletedAt = DateTimeOffset.UnixEpoch, DurationMs = 1, TotalCount = 1, PassedCount = 1,
            FailedCount = 0, SkippedCount = 0, InconclusiveCount = 0, Suites = Array.Empty<TestSuite>(),
        });

        Assert.Equal(CapturingHandler.ComponentVersionId, r.ComponentVersionId);
        Assert.Equal(CapturingHandler.ReportId, r.TestRunReportId);
        Assert.Equal(2, r.SuitesCount);
        Assert.Equal(56, r.CasesCount);
    }

    [Fact]
    public async Task PostScanRuns_Returns_The_Build_And_Upsert_Count()
    {
        var r = await NewClient().PostScanRunsAsync(new ScanRunsIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v",
            Receipts = Array.Empty<ScanRunReceipt>(),
        });

        Assert.Equal(CapturingHandler.ComponentVersionId, r.ComponentVersionId);
        Assert.Equal(4, r.ReceiptsUpserted);
    }

    [Fact]
    public async Task PostPosture_Returns_How_The_Set_Was_Applied()
    {
        var r = await NewClient().PostPostureAsync(new PostureIngestRequest
        {
            Client = "c", Project = "p",
            Observations = new[] { new PostureObservation { CheckId = "codeowners", Status = PostureStatus.Fail } },
        });

        Assert.Equal(CapturingHandler.ProjectId, r.ProjectId);
        Assert.Equal(5, r.Accepted);
        Assert.Equal(2, r.Created);
        Assert.Equal(3, r.Updated);
    }

    [Fact]
    public async Task PostSbomProvenance_Returns_The_Stored_Attestation()
    {
        var snapshotId = Guid.NewGuid();
        var r = await NewClient().PostSbomProvenanceAsync(snapshotId, "{\"payloadType\":\"application/vnd.in-toto+json\"}");

        Assert.Equal(snapshotId, r.SnapshotId);
        Assert.Equal("dsse", r.ProvenanceType);
        Assert.Equal(new DateTimeOffset(2026, 10, 31, 15, 0, 0, TimeSpan.Zero), r.UploadedAt);
    }

    [Fact]
    public async Task PostSbomProvenance_Tolerates_Unrecognized_Type_As_Null()
    {
        // The sink stores provenance it cannot classify with a null type. That must not fail the call.
        var id = Guid.NewGuid();
        var r = await NewClient(_ => Ok($$"""{"snapshotId":"{{id}}","provenanceType":null,"uploadedAt":null}"""))
            .PostSbomProvenanceAsync(id, "{}");
        Assert.Equal(id, r.SnapshotId);
        Assert.Null(r.ProvenanceType);
        Assert.Null(r.UploadedAt);
    }

    [Fact]
    public async Task Empty_Success_Body_Fails_Loudly_Not_Silently()
    {
        // A 2xx with no body means the sink did not say what it stored. That is the exact blind spot
        // TAM-293 closes, so surface it rather than returning a zeroed response.
        var client = NewClient(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("") });

        var ex = await Assert.ThrowsAsync<ApiException>(() => client.PostScanRunsAsync(new ScanRunsIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v", Receipts = Array.Empty<ScanRunReceipt>(),
        }));
        Assert.Contains("response was empty", ex.Message);

        var pex = await Assert.ThrowsAsync<ApiException>(() => client.PostSbomProvenanceAsync(Guid.NewGuid(), "{}"));
        Assert.Contains("response was empty", pex.Message);
    }

    [Fact]
    public async Task Response_Missing_A_Required_Id_Is_Rejected()
    {
        // The build id is the field strata needed most, so it is required. A body without it is not a success.
        var client = NewClient(_ => Ok("""{"modulesCount":3}"""));
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(() => client.PostCoverageAsync(new CoverageIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v", ToolName = "OpenCover",
            CompletedAt = DateTimeOffset.UnixEpoch, SequenceCoverage = 1m, BranchCoverage = 1m,
            CoveredSequences = 1, TotalSequences = 1, Modules = Array.Empty<CoverageModule>(),
        }));
    }

    // ---- TAM-294 follow-through: ingest-suited timeout + honest User-Agent ----

    [Fact]
    public void Defaults_RequestTimeout_To_The_Ingest_Timeout_Not_HttpClients_100s()
    {
        using var client = new TampIngestClient(BaseUri, Token);
        Assert.Equal(TimeSpan.FromMinutes(5), TampIngestClient.DefaultIngestTimeout);
        Assert.Equal(TampIngestClient.DefaultIngestTimeout, client.RequestTimeout);
    }

    [Fact]
    public void RequestTimeout_Is_Still_Tunable_Per_Instance()
    {
        using var client = new TampIngestClient(BaseUri, Token) { RequestTimeout = TimeSpan.FromMinutes(20) };
        Assert.Equal(TimeSpan.FromMinutes(20), client.RequestTimeout);
    }

    [Fact]
    public void User_Agent_Reports_The_Real_Package_Version()
    {
        var http = new HttpClient(new CapturingHandler());
        using var _ = new TampIngestClient(BaseUri, Token, http);
        var ua = http.DefaultRequestHeaders.UserAgent.ToString();
        Assert.Matches(@"^Tamp\.Ingest\.V1/\d+\.\d+\.\d+$", ua);   // no "+sha" build metadata
        Assert.NotEqual("Tamp.Ingest.V1/0.2.0", ua);                     // the old hard-coded value
    }
}

using System.Net;
using System.Text;
using Tamp;
using Tamp.Http;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// TFND-265 / TFND-266 (ingest-v1#12). The ingest responses echo the build the sink RESOLVED, and
/// <c>GET /ingest/builds/{commitSha}</c> reads back everything it holds, so a producer can verify instead of
/// trusting a 2xx. Shapes follow the sink's live <c>/openapi/v1.json</c> (build 0.1.0-alpha+6cd91fc).
/// </summary>
public class BuildEvidenceTests
{
    private static readonly Uri BaseUri = new("https://sink.example.com/");
    private static readonly Secret Token = new("test-token", "cli_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private const string Sha = "6651019abcdef6651019abcdef6651019abcdef0";

    private static (TampIngestClient, CapturingHandler) NewClient(Func<HttpRequestMessage, HttpResponseMessage>? responder = null)
    {
        var h = new CapturingHandler();
        if (responder is not null) h.Responder = responder;
        return (new TampIngestClient(BaseUri, Token, new HttpClient(h)), h);
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string json) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    // The sink's BuildEvidenceResponse, every section populated.
    private const string Evidence = """
    {
      "projectId": "44f1f80c-976f-4233-89fc-64a6de33520b", "client": "Tamp", "project": "tamp-core",
      "commitSha": "6651019abcdef6651019abcdef6651019abcdef0",
      "builds": [ {
        "build": { "componentVersionId": "d2783ce8-bd2f-4d38-a736-4bfa64605691", "versionString": "1.17.6-nightly",
                   "commitSha": "6651019abcdef6651019abcdef6651019abcdef0", "flavor": null, "branch": "main",
                   "pullRequestRef": null, "createdAt": "2026-10-31T15:40:00+00:00" },
        "coverage": { "toolName": "coverlet", "toolVersion": "5.5.1", "sequenceCoverage": 81.4, "branchCoverage": 70.2,
                      "coveredSequences": 8140, "totalSequences": 10000, "coveredBranches": 702, "totalBranches": 1000,
                      "modules": 11, "sourceFiles": 324, "classes": 450, "ingestedAt": "2026-10-31T15:45:00+00:00" },
        "testResults": { "toolName": "VSTest", "toolVersion": null, "total": 5000, "passed": 4998, "failed": 0, "skipped": 2,
                         "inconclusive": 0, "suites": 102, "cases": 5000, "completedAt": "2026-10-31T15:44:00+00:00",
                         "ingestedAt": "2026-10-31T15:45:10+00:00" },
        "sbom": { "snapshotId": "bcc139ab-e0c9-4e01-9a82-31859a3e336e", "toolName": "Tamp.Sbom", "toolVersion": "1.13.0",
                  "specVersion": "1.6", "serialNumber": "urn:uuid:1", "components": 77, "vulnerabilities": 0,
                  "provenanceType": null, "provenanceVerified": false, "ingestedAt": "2026-10-31T15:43:00+00:00" },
        "findings": [ { "scanner": "OpenGrep", "total": 4, "open": 2, "openBySeverity": { "High": 1, "Medium": 1 } },
                      { "scanner": "SomeFutureScanner", "total": 1, "open": 1, "openBySeverity": { "Low": 1 } } ],
        "scanRuns": [ { "scanner": "OpenGrep", "status": "Succeeded", "findingsCount": 4, "toolName": "OpenGrep",
                        "toolVersion": "1.2.0", "completedAt": "2026-10-31T15:42:00+00:00", "ingestedAt": "2026-10-31T15:46:00+00:00" } ],
        "qualityGate": { "status": "PASS", "source": "SonarCloud", "analysisId": "AZ1", "observedAt": "2026-10-31T15:41:00+00:00",
                         "ingestedAt": "2026-10-31T15:46:30+00:00" },
        "containerImage": null,
        "analysisCoverage": { "languages": 2, "gapLanguages": null, "observedAt": "2026-10-31T15:41:00+00:00",
                              "ingestedAt": "2026-10-31T15:46:40+00:00" },
        "scanUsage": { "observations": 0, "inputTokens": 0, "outputTokens": 0 },
        "conformanceVerdicts": 4, "diagnostics": 146
      } ]
    }
    """;

    [Fact]
    public async Task Read_Uses_Get_On_The_Commit_Path_With_Escaped_Query_And_Bearer()
    {
        var (client, h) = NewClient(_ => Json(HttpStatusCode.OK, Evidence));

        await client.ReadBuildEvidenceAsync(Sha, project: "tamp core", flavor: "release/x", pullRequestRef: "refs/pull/7/merge");

        var sent = Assert.Single(h.Sent);
        Assert.Equal(HttpMethod.Get, sent.Method);
        Assert.Equal($"/ingest/builds/{Sha}", sent.Path);
        Assert.Equal("?project=tamp%20core&flavor=release%2Fx&pullRequestRef=refs%2Fpull%2F7%2Fmerge", sent.Query);
        Assert.Null(sent.Body);
        Assert.Equal("Bearer cli_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA", sent.Authorization);
    }

    [Fact]
    public async Task Read_Omits_The_Query_When_No_Filters_Are_Given()
    {
        var (client, h) = NewClient(_ => Json(HttpStatusCode.OK, Evidence));
        await client.ReadBuildEvidenceAsync("6651019");
        Assert.Equal("/ingest/builds/6651019", h.Sent.Single().Path);
        Assert.Empty(h.Sent.Single().Query);
    }

    [Fact]
    public async Task Read_Deserializes_Every_Section()
    {
        var (client, _) = NewClient(_ => Json(HttpStatusCode.OK, Evidence));

        var r = await client.ReadBuildEvidenceAsync(Sha);

        Assert.NotNull(r);
        Assert.Equal("tamp-core", r!.Project);
        var b = Assert.Single(r.Builds);
        Assert.Equal(Guid.Parse("d2783ce8-bd2f-4d38-a736-4bfa64605691"), b.Build.ComponentVersionId);
        Assert.Equal(Sha, b.Build.CommitSha);
        Assert.Equal("main", b.Build.Branch);
        Assert.Null(b.Build.Flavor);
        Assert.Equal(81.4, b.Coverage!.SequenceCoverage);
        Assert.Equal(450, b.Coverage.Classes);
        Assert.Equal(102, b.TestResults!.Suites);
        Assert.Null(b.TestResults.ToolVersion);
        Assert.Equal(77, b.Sbom!.Components);
        Assert.False(b.Sbom.ProvenanceVerified);
        Assert.Equal(2, b.Findings.Count);
        Assert.Equal(1, b.Findings[0].OpenBySeverity["High"]);
        Assert.Equal("SomeFutureScanner", b.Findings[1].Scanner);   // unknown-to-the-client scanner still reads
        Assert.Equal("Succeeded", Assert.Single(b.ScanRuns).Status);
        Assert.Equal("PASS", b.QualityGate!.Status);
        Assert.Null(b.ContainerImage);                               // null = not stored
        Assert.Equal(2, b.AnalysisCoverage!.Languages);
        Assert.Equal(0, b.ScanUsage!.InputTokens);
        Assert.Equal(4, b.ConformanceVerdicts);
        Assert.Equal(146, b.Diagnostics);
    }

    [Fact]
    public async Task Read_Returns_Null_On_404_Because_The_Sink_Never_Confirms_Existence()
    {
        var (client, _) = NewClient(_ => Json(HttpStatusCode.NotFound, """{"error":"not found"}"""));
        Assert.Null(await client.ReadBuildEvidenceAsync(Sha));
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task Read_Throws_On_Other_Client_Errors(HttpStatusCode code)
    {
        var (client, _) = NewClient(_ => Json(code, """{"error":"nope"}"""));
        var ex = await Assert.ThrowsAsync<ApiClientException>(() => client.ReadBuildEvidenceAsync(Sha));
        Assert.Equal(code, ex.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Read_Rejects_An_Empty_Sha(string sha)
    {
        var (client, _) = NewClient();
        await Assert.ThrowsAsync<ArgumentException>(() => client.ReadBuildEvidenceAsync(sha));
    }

    [Fact]
    public async Task Read_Tolerates_Empty_Sections_And_Missing_Lists()
    {
        var (client, _) = NewClient(_ => Json(HttpStatusCode.OK, """
            { "projectId": "44f1f80c-976f-4233-89fc-64a6de33520b", "client": "Tamp", "project": "tamp-core", "commitSha": "abc1234",
              "builds": [ { "build": { "componentVersionId": "d2783ce8-bd2f-4d38-a736-4bfa64605691", "versionString": "1",
                                       "commitSha": null, "flavor": null, "branch": null, "pullRequestRef": null,
                                       "createdAt": "2026-10-31T15:40:00+00:00" },
                            "coverage": null, "testResults": null, "sbom": null, "findings": [], "scanRuns": [],
                            "qualityGate": null, "containerImage": null, "analysisCoverage": null, "scanUsage": null,
                            "conformanceVerdicts": 0, "diagnostics": 0 } ] }
            """));
        var b = Assert.Single((await client.ReadBuildEvidenceAsync("abc1234"))!.Builds);
        Assert.Null(b.Coverage);
        Assert.Empty(b.Findings);
        Assert.Empty(b.ScanRuns);
    }

    // ---- TFND-266 echo on the ingest responses ----

    [Fact]
    public async Task Ingest_Response_Carries_The_Resolved_Build()
    {
        var (client, _) = NewClient();   // sink-shaped default; coverage carries `build`
        var r = await client.PostCoverageAsync(new CoverageIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v", ToolName = "coverlet",
            CompletedAt = DateTimeOffset.UnixEpoch, SequenceCoverage = 1m, BranchCoverage = 1m,
            CoveredSequences = 1, TotalSequences = 1, Modules = Array.Empty<CoverageModule>(),
        });

        Assert.NotNull(r.Build);
        Assert.Equal(CapturingHandler.ComponentVersionId, r.Build!.ComponentVersionId);
        Assert.Equal(Sha, r.Build.CommitSha);
        Assert.Equal("1.2.3", r.Build.VersionString);
        Assert.Equal("main", r.Build.Branch);
    }

    [Fact]
    public async Task Ingest_Response_Build_Is_Null_From_A_Sink_That_Predates_The_Echo()
    {
        var (client, _) = NewClient();   // the default scan-runs body has no `build`
        var r = await client.PostScanRunsAsync(new ScanRunsIngestRequest
        {
            Client = "c", Project = "p", Component = "comp", Version = "v", Receipts = Array.Empty<ScanRunReceipt>(),
        });
        Assert.Null(r.Build);
    }

    [Fact]
    public void Findings_Response_Reads_The_Cve_Counts()
    {
        var r = System.Text.Json.JsonSerializer.Deserialize<FindingsIngestResponse>(
            """{"componentVersionId":"d2783ce8-bd2f-4d38-a736-4bfa64605691","findingsInserted":1,"cvesAttached":3,"cvesUnattached":2}""",
            IngestJsonOptions.Default)!;
        Assert.Equal(3, r.CvesAttached);
        Assert.Equal(2, r.CvesUnattached);
    }
}

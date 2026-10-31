using System.Net;
using System.Text;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// Test-only <see cref="HttpMessageHandler"/> that captures every outgoing request and
/// returns a configurable response. Use one instance per test (no shared state).
/// </summary>
internal sealed class CapturingHandler : HttpMessageHandler
{
    public List<CapturedRequest> Sent { get; } = new();

    /// <summary>
    /// Default response: what tamp.findings actually returns for each ingest route (camelCase, the shapes of
    /// its <c>*IngestResponse</c> records), so the typed-response path is exercised by every test (TAM-293).
    /// Unrecognized routes get 204 No Content. Override for error and edge cases.
    /// </summary>
    public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; } = SinkResponse;

    /// <summary>Fixed ids the sink-shaped default responses carry, for assertions.</summary>
    public static readonly Guid ComponentVersionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid ReportId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    public static readonly Guid ProjectId = Guid.Parse("33333333-3333-3333-3333-333333333333");

    public static HttpResponseMessage SinkResponse(HttpRequestMessage request)
    {
        var path = request.RequestUri!.AbsolutePath;
        var json = path switch
        {
            "/ingest/coverage" =>
                $$"""{"componentVersionId":"{{ComponentVersionId}}","coverageReportId":"{{ReportId}}","modulesCount":3,"classesCount":41,"sourceFilesCount":17}""",
            "/ingest/test-results" =>
                $$"""{"componentVersionId":"{{ComponentVersionId}}","testRunReportId":"{{ReportId}}","suitesCount":2,"casesCount":56}""",
            "/ingest/scan-runs" =>
                $$"""{"componentVersionId":"{{ComponentVersionId}}","receiptsUpserted":4}""",
            "/ingest/posture" =>
                $$"""{"projectId":"{{ProjectId}}","accepted":5,"created":2,"updated":3}""",
            _ when path.StartsWith("/ingest/sbom-snapshots/", StringComparison.Ordinal) && path.EndsWith("/provenance", StringComparison.Ordinal) =>
                $$"""{"snapshotId":"{{path.Split('/')[3]}}","provenanceType":"dsse","uploadedAt":"2026-10-31T15:00:00+00:00"}""",
            _ => null,
        };
        return json is null
            ? new HttpResponseMessage(HttpStatusCode.NoContent)
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var contentType = request.Content?.Headers.ContentType?.MediaType;
        var authHeader = request.Headers.Authorization?.ToString();
        Sent.Add(new CapturedRequest(request.Method, request.RequestUri!, body, contentType, authHeader));
        return Responder(request);
    }
}

internal sealed record CapturedRequest(HttpMethod Method, Uri Uri, string? Body, string? ContentType, string? Authorization)
{
    public string Path => Uri.AbsolutePath;
    public string Query => Uri.Query;
}

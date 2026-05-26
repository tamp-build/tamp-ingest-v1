using System.Net.Http.Headers;
using System.Text;
using Tamp.Http;
using Tamp.Sarif;
using Tamp.Sbom;

namespace Tamp.Ingest.V1;

/// <summary>
/// Typed C# client for the <c>tamp-ingest-v1</c> egress contract.
/// Wraps the seven ingest endpoints any compliant sink (tamp.findings,
/// DefectDojo bridge, evidence vault, etc.) accepts.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Auth.</strong> Always bearer — sinks issue <c>cli_</c>-prefixed
/// client tokens (any project beneath one client) or <c>prj_</c>-prefixed
/// project-scoped tokens. Wrap the token in <see cref="ApiCredential.Bearer"/>
/// so it stays in a <see cref="Secret"/> (TAMP004-friendly; never leaked to
/// logs / process listings).
/// </para>
/// <para>
/// <strong>Hierarchy.</strong> Every endpoint except <see cref="PostSbomProvenanceAsync"/>
/// identifies the Client → Project → Component → ComponentVersion tuple via
/// the <see cref="IngestBuildContext"/> record (encoded as query params).
/// </para>
/// <para>
/// <strong>SARIF / SBOM bodies.</strong> Serialized via <see cref="SarifWriter.Serialize"/>
/// / <see cref="SbomWriter.Serialize"/> (preserves SARIF case sensitivity); other
/// DTOs serialize via the base client's camelCase / drop-null options.
/// </para>
/// </remarks>
public sealed class TampIngestClient : TampApiClient
{
    /// <summary>
    /// Construct the client.
    /// </summary>
    /// <param name="baseUri">The ingest sink base URI (e.g. <c>https://tamp-findings.brewingcoder.com</c>).</param>
    /// <param name="token">Bearer token issued by the sink (<c>cli_</c>… or <c>prj_</c>…).</param>
    /// <param name="httpClient">Optional pre-configured <see cref="HttpClient"/>. When null the client owns its own and disposes it on <see cref="TampApiClient.Dispose"/>.</param>
    public TampIngestClient(Uri baseUri, Secret token, HttpClient? httpClient = null)
        : base(baseUri, ApiCredential.Bearer(token), http: httpClient, userAgent: "Tamp.Ingest.V1/0.1.0")
    {
    }

    /// <summary>
    /// <c>POST /ingest/sbom</c> — push a CycloneDX BOM for the build identified by <paramref name="ctx"/>.
    /// Returns the sink-assigned snapshot id which uniquely identifies this BOM revision
    /// (use it to attach provenance via <see cref="PostSbomProvenanceAsync"/>).
    /// </summary>
    public async Task<SbomSnapshotResponse> PostSbomAsync(IngestBuildContext ctx, CycloneDxBom bom, CancellationToken ct = default)
    {
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));
        if (bom is null) throw new ArgumentNullException(nameof(bom));

        var uri = $"/ingest/sbom?{ctx.ToQueryString()}";
        var body = SbomWriter.Serialize(bom);
        return await PostJsonStringAsync<SbomSnapshotResponse>(uri, body, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /ingest/sbom/{snapshotId}/provenance</c> — attach SLSA / in-toto provenance to
    /// a previously-ingested SBOM snapshot. <paramref name="provenanceJson"/> is the
    /// already-serialized provenance document (any v0.2 / v1 SLSA shape; sink stores opaque).
    /// </summary>
    public async Task PostSbomProvenanceAsync(Guid snapshotId, string provenanceJson, CancellationToken ct = default)
    {
        if (snapshotId == Guid.Empty) throw new ArgumentException("snapshotId must be non-empty.", nameof(snapshotId));
        if (string.IsNullOrEmpty(provenanceJson)) throw new ArgumentException("provenanceJson must be non-empty.", nameof(provenanceJson));

        var uri = $"/ingest/sbom/{snapshotId:D}/provenance";
        await PostJsonStringAsync(uri, provenanceJson, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /ingest/findings</c> — push a SARIF 2.1.0 log for one scanner run.
    /// </summary>
    public async Task PostFindingsAsync(IngestBuildContext ctx, ScannerKind scanner, SarifLog log, CancellationToken ct = default)
    {
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));
        if (log is null) throw new ArgumentNullException(nameof(log));

        var uri = $"/ingest/findings?{ctx.ToQueryString()}&scannerKind={Uri.EscapeDataString(scanner.ToWire())}";
        var body = SarifWriter.Serialize(log);
        await PostJsonStringAsync(uri, body, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /ingest/coverage</c> — push the aggregate line/branch coverage rollup for the build.
    /// </summary>
    public async Task PostCoverageAsync(IngestBuildContext ctx, CoverageIngestRequestDto coverage, CancellationToken ct = default)
    {
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));
        if (coverage is null) throw new ArgumentNullException(nameof(coverage));

        var uri = $"/ingest/coverage?{ctx.ToQueryString()}";
        await PostJsonAsync(uri, coverage, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /ingest/test-results</c> — push the aggregate test-result rollup for the build.
    /// </summary>
    public async Task PostTestResultsAsync(IngestBuildContext ctx, TestResultsIngestRequestDto results, CancellationToken ct = default)
    {
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));
        if (results is null) throw new ArgumentNullException(nameof(results));

        var uri = $"/ingest/test-results?{ctx.ToQueryString()}";
        await PostJsonAsync(uri, results, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /ingest/scan-runs</c> — push one or more per-scanner receipts for the build.
    /// Sinks treat the receipt set as authoritative for the "last scan" status board.
    /// </summary>
    public async Task PostScanRunsAsync(IngestBuildContext ctx, IEnumerable<ScanRunReceipt> receipts, CancellationToken ct = default)
    {
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));
        if (receipts is null) throw new ArgumentNullException(nameof(receipts));

        // Materialize once — the base client serializes by GetType(), so the
        // declared static type matters for property casing.
        var list = (IReadOnlyList<ScanRunReceipt>)receipts.ToArray();
        if (list.Count == 0) return; // no-op rather than POST an empty array

        var uri = $"/ingest/scan-runs?{ctx.ToQueryString()}";
        await PostJsonAsync(uri, list, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>POST /ingest/sbom-vulnerabilities</c> — push vulnerability findings sourced from
    /// non-SARIF tooling (Grype / OSV / GHSA rollups). SARIF-emitting scanners route via
    /// <see cref="PostFindingsAsync"/> instead.
    /// </summary>
    public async Task PostSbomVulnerabilitiesAsync(IngestBuildContext ctx, IEnumerable<SbomVulnerability> vulns, CancellationToken ct = default)
    {
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));
        if (vulns is null) throw new ArgumentNullException(nameof(vulns));

        var list = (IReadOnlyList<SbomVulnerability>)vulns.ToArray();
        if (list.Count == 0) return;

        var uri = $"/ingest/sbom-vulnerabilities?{ctx.ToQueryString()}";
        await PostJsonAsync(uri, list, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// POST a pre-serialized JSON string body (used for SARIF / SBOM where the
    /// case-sensitive wire shape comes from <see cref="SarifWriter"/> / <see cref="SbomWriter"/>
    /// rather than the base client's camelCase serializer).
    /// </summary>
    private async Task PostJsonStringAsync(string relativeUri, string jsonBody, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, relativeUri)
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, MediaTypeHeaderValue.Parse("application/json").MediaType!),
        };
        using var response = await SendRawAsync(request, ct: ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var bodyText = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new ApiException(response.StatusCode, response.RequestMessage?.RequestUri?.ToString(), HttpMethod.Post.Method, bodyText,
                $"POST {relativeUri} -> {(int)response.StatusCode} {response.ReasonPhrase}");
        }
    }

    /// <summary>POST a pre-serialized JSON string body and deserialize the response.</summary>
    private async Task<T> PostJsonStringAsync<T>(string relativeUri, string jsonBody, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, relativeUri)
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, MediaTypeHeaderValue.Parse("application/json").MediaType!),
        };
        using var response = await SendRawAsync(request, ct: ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var bodyText = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            throw new ApiException(response.StatusCode, response.RequestMessage?.RequestUri?.ToString(), HttpMethod.Post.Method, bodyText,
                $"POST {relativeUri} -> {(int)response.StatusCode} {response.ReasonPhrase}");
        }
        var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var value = await System.Text.Json.JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, ct).ConfigureAwait(false);
        return value ?? throw new ApiException(response.StatusCode, response.RequestMessage?.RequestUri?.ToString(), HttpMethod.Post.Method, null,
            $"JSON for POST {relativeUri} deserialized to null.");
    }
}

/// <summary>Response shape from <c>POST /ingest/sbom</c>.</summary>
public sealed record SbomSnapshotResponse
{
    /// <summary>Sink-assigned snapshot id. Use with <see cref="TampIngestClient.PostSbomProvenanceAsync"/>.</summary>
    public required Guid SnapshotId { get; init; }

    /// <summary>True when this snapshot is the first ingest for this hierarchy tuple+version.</summary>
    public bool Created { get; init; }
}

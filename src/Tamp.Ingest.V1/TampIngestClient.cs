using Tamp.Http;
using Tamp.Sarif;
using Tamp.Sbom;

namespace Tamp.Ingest.V1;

/// <summary>
/// Typed C# client for the <c>tamp-ingest-v1</c> egress contract (spec v1.2).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Wire shape (spec v1.2):</strong> every <c>/ingest/*</c> body carries
/// the hierarchy tuple flat-inline at the root. No <c>?clientName=</c> / etc.
/// query params anywhere. SBOM bodies are normalized (not raw CycloneDX) —
/// pre-shape with <see cref="CycloneDxSbomMapper.BuildRequest"/>. Findings bodies
/// are flat per-row (not raw SARIF) — pre-shape with
/// <see cref="SarifFindingsMapper.BuildRequest"/>.
/// </para>
/// <para>
/// <strong>Auth.</strong> Bearer token wrapped in a <see cref="Secret"/>.
/// <c>cli_…</c> binds to a Client by name (must match <c>client</c> field in body);
/// <c>prj_…</c> binds to a Project (must match <c>project</c>).
/// </para>
/// <para>
/// <strong>Serialization.</strong> Uses <see cref="IngestJsonOptions.Default"/>
/// (camelCase, drop-nulls, PascalCase string enums).
/// </para>
/// </remarks>
public sealed class TampIngestClient : TampApiClient
{
    /// <summary>
    /// Construct the client.
    /// </summary>
    /// <param name="baseUri">The ingest sink base URI (e.g. <c>https://tamp-findings.brewingcoder.com</c>).</param>
    /// <param name="token">Bearer token (<c>cli_</c>… or <c>prj_</c>…).</param>
    /// <param name="httpClient">Optional shared <see cref="HttpClient"/>. When null the client owns its own.</param>
    /// <remarks>
    /// <see cref="TampApiClient.RequestTimeout"/> defaults to <see cref="DefaultIngestTimeout"/>. If you pass
    /// <paramref name="httpClient"/>, its own <see cref="HttpClient.Timeout"/> (100 s unless you changed it)
    /// still applies and wins when shorter. A timeout from it is reported as such (Tamp.Http
    /// <see cref="ApiTimeoutException.IsHttpClientTimeout"/>).
    /// </remarks>
    public TampIngestClient(Uri baseUri, Secret token, HttpClient? httpClient = null)
        : base(baseUri, ApiCredential.Bearer(token), http: httpClient, userAgent: UserAgent)
    {
        RequestTimeout = DefaultIngestTimeout;
    }

    /// <summary>
    /// Default per-request limit for ingest calls: 5 minutes (TAM-294). Replace-on-ingest uploads with large SBOMs
    /// or coverage trees can legitimately run longer than HttpClient's 100 s. Change it per instance through
    /// <see cref="TampApiClient.RequestTimeout"/>.
    /// </summary>
    public static readonly TimeSpan DefaultIngestTimeout = TimeSpan.FromMinutes(5);

    private static readonly string UserAgent = "Tamp.Ingest.V1/" + PackageVersion();

    private static string PackageVersion()
    {
        var info = typeof(TampIngestClient).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?.InformationalVersion;
        if (string.IsNullOrEmpty(info)) return typeof(TampIngestClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        var plus = info.IndexOf('+');   // strip SourceLink's "+<commit sha>" build metadata
        return plus >= 0 ? info[..plus] : info;
    }

    /// <inheritdoc />
    protected override System.Text.Json.JsonSerializerOptions JsonOptions => IngestJsonOptions.Default;

    /// <summary><c>POST /ingest/sbom</c> — push a normalized SBOM (spec v1.2 §2.1).</summary>
    public Task<SbomIngestResponse> PostSbomAsync(SbomIngestRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        return PostJsonAsync<SbomIngestResponse>("/ingest/sbom", request, ct);
    }

    /// <summary>Convenience overload that maps the CycloneDX BOM in-flight.</summary>
    public Task<SbomIngestResponse> PostSbomAsync(
        IngestHierarchy hierarchy,
        CycloneDxBom bom,
        string? toolName = null,
        string? toolVersion = null,
        IReadOnlyList<SbomMetadataTool>? metadataTools = null,
        CancellationToken ct = default)
        => PostSbomAsync(CycloneDxSbomMapper.BuildRequest(hierarchy, bom, toolName, toolVersion, metadataTools), ct);

    /// <summary>
    /// <c>POST /ingest/sbom-snapshots/{snapshotId}/provenance</c> — attach SLSA / in-toto / DSSE
    /// provenance to a previously-ingested SBOM snapshot (spec v1.2 §2.2).
    /// </summary>
    /// <returns>The attestation the sink now holds: the snapshot, the detected provenance type and the upload time.</returns>
    public async Task<SbomProvenanceResponse> PostSbomProvenanceAsync(Guid snapshotId, string provenanceJson, CancellationToken ct = default)
    {
        if (snapshotId == Guid.Empty) throw new ArgumentException("snapshotId must be non-empty.", nameof(snapshotId));
        if (string.IsNullOrEmpty(provenanceJson)) throw new ArgumentException("provenanceJson must be non-empty.", nameof(provenanceJson));

        var uri = $"/ingest/sbom-snapshots/{snapshotId:D}/provenance";
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new System.Net.Http.StringContent(provenanceJson, System.Text.Encoding.UTF8, "application/json"),
        };
        using var response = await SendRawAsync(request, ct: ct).ConfigureAwait(false);
        await ThrowIfNotSuccessAsync(response, "POST " + uri, ct).ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(body))
            throw new ApiException(response.StatusCode, response.RequestMessage?.RequestUri?.ToString(), HttpMethod.Post.Method, null,
                $"Expected JSON body for POST {uri} but response was empty.");
        return System.Text.Json.JsonSerializer.Deserialize<SbomProvenanceResponse>(body, JsonOptions)
            ?? throw new ApiException(response.StatusCode, response.RequestMessage?.RequestUri?.ToString(), HttpMethod.Post.Method, body,
                $"JSON for POST {uri} deserialized to null.");
    }

    /// <summary><c>POST /ingest/findings</c> — push a flat findings array (spec v1.2 §2.3).</summary>
    public Task<FindingsIngestResponse> PostFindingsAsync(FindingsIngestRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        return PostJsonAsync<FindingsIngestResponse>("/ingest/findings", request, ct);
    }

    /// <summary>Convenience overload that maps a <see cref="SarifLog"/> in-flight.</summary>
    public Task<FindingsIngestResponse> PostFindingsAsync(
        IngestHierarchy hierarchy,
        ScannerKind scanner,
        SarifLog log,
        string? defaultSubCategory = null,
        CancellationToken ct = default)
        => PostFindingsAsync(SarifFindingsMapper.BuildRequest(hierarchy, scanner, log, defaultSubCategory), ct);

    /// <summary><c>POST /ingest/coverage</c> — push the normalized coverage rollup (spec v1.2 §2.4).</summary>
    public Task<CoverageIngestResponse> PostCoverageAsync(CoverageIngestRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        return PostJsonAsync<CoverageIngestResponse>("/ingest/coverage", request, ct);
    }

    /// <summary><c>POST /ingest/test-results</c> — push the normalized test-result rollup (spec v1.2 §2.5).</summary>
    public Task<TestResultsIngestResponse> PostTestResultsAsync(TestResultsIngestRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        return PostJsonAsync<TestResultsIngestResponse>("/ingest/test-results", request, ct);
    }

    /// <summary><c>POST /ingest/scan-runs</c> — push per-scanner receipts (spec v1.2 §2.6).</summary>
    public Task<ScanRunsIngestResponse> PostScanRunsAsync(ScanRunsIngestRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        return PostJsonAsync<ScanRunsIngestResponse>("/ingest/scan-runs", request, ct);
    }

    /// <summary>
    /// <c>POST /sbom-vulnerabilities/upsert</c> — push OSV-Scanner CVE rows against a previously-ingested
    /// SBOM snapshot (spec v1.2 §2.7). Note: <strong>no <c>/ingest/</c> prefix</strong>.
    /// </summary>
    public Task<SbomVulnerabilitiesUpsertResponse> PostSbomVulnerabilitiesUpsertAsync(
        SbomVulnerabilitiesUpsertRequest request,
        CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        return PostJsonAsync<SbomVulnerabilitiesUpsertResponse>("/sbom-vulnerabilities/upsert", request, ct);
    }

    /// <summary>
    /// <c>POST /ingest/posture</c> — push repo/org security-posture observations (spec v1.3 §2.8, TAM-290).
    /// </summary>
    /// <remarks>
    /// Posture is repo/org-scoped, so <see cref="PostureIngestRequest"/> carries no build/commit hierarchy.
    /// Post the full observation set every run and report facts (including <see cref="PostureStatus.Unknown"/>)
    /// rather than judgements — findings owns gating. An unknown <see cref="PostureObservation.CheckId"/>
    /// rejects the whole batch with <c>400</c>.
    /// </remarks>
    public Task<PostureIngestResponse> PostPostureAsync(PostureIngestRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        return PostJsonAsync<PostureIngestResponse>("/ingest/posture", request, ct);
    }

    private async Task ThrowIfNotSuccessAsync(HttpResponseMessage response, string label, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        throw new ApiException(response.StatusCode, response.RequestMessage?.RequestUri?.ToString(), HttpMethod.Post.Method, body,
            $"{label} -> {(int)response.StatusCode} {response.ReasonPhrase}");
    }
}

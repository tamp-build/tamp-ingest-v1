namespace Tamp.Ingest.V1;

/// <summary>
/// Body for <c>POST /sbom-vulnerabilities/upsert</c> (spec v1.2 §2.7).
/// </summary>
/// <remarks>
/// <para>
/// Note path: <strong>no <c>/ingest/</c> prefix</strong> (v1.0 / v1.1 had it wrong; v1.2 corrected).
/// </para>
/// <para>
/// Keys off <see cref="SnapshotId"/> returned by <see cref="SbomIngestResponse.SbomSnapshotId"/>.
/// Pair the SBOM POST and the vuln upsert in the same build step so the snapshot id is in hand.
/// Sink matches <c>(packageName, packageVersion)</c> against the snapshot's components and reports
/// match / unmatch counts in the response.
/// </para>
/// </remarks>
public sealed record SbomVulnerabilitiesUpsertRequest
{
    /// <summary>SBOM snapshot id returned by <c>POST /ingest/sbom</c>.</summary>
    public required Guid SnapshotId { get; init; }

    public required IReadOnlyList<SbomVulnerability> Vulnerabilities { get; init; }
}

/// <summary>One vulnerability row in the upsert payload (spec v1.2 §2.7).</summary>
public sealed record SbomVulnerability
{
    /// <summary>Package name. Sink matches exact <c>(packageName, packageVersion)</c> against snapshot components.</summary>
    public required string PackageName { get; init; }
    public required string PackageVersion { get; init; }
    /// <summary>Advisory id — <c>"CVE-…"</c>, <c>"GHSA-…"</c>, <c>"OSV-…"</c>.</summary>
    public required string AdvisoryId { get; init; }
    /// <summary>Resolved severity (PascalCase per spec §3.2).</summary>
    public required Severity Severity { get; init; }
    public string? Title { get; init; }
    public string? Description { get; init; }
    public string? ReferenceUrl { get; init; }
}

/// <summary>Response from <c>POST /sbom-vulnerabilities/upsert</c> (spec v1.2 §2.7).</summary>
public sealed record SbomVulnerabilitiesUpsertResponse
{
    public required Guid SnapshotId { get; init; }
    /// <summary>Count of vulns whose <c>(packageName, packageVersion)</c> matched a snapshot component.</summary>
    public int Matched { get; init; }
    /// <summary>Count that didn't match — possible if scanner ran against a wider set than the SBOM.</summary>
    public int Unmatched { get; init; }
    public int Inserted { get; init; }
    public int Updated { get; init; }
}

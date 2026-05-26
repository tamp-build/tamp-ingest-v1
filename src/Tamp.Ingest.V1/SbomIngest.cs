namespace Tamp.Ingest.V1;

/// <summary>
/// Body for <c>POST /ingest/sbom</c> (spec v1.2 §2.1). Normalized — NOT raw CycloneDX.
/// </summary>
/// <remarks>
/// Adopter transforms CycloneDX (1.4 / 1.5+) → this DTO via
/// <see cref="CycloneDxSbomMapper.FromCycloneDx"/>. Hierarchy is flat-inline
/// (every field on <see cref="IngestHierarchy"/> serializes at the request root).
/// </remarks>
public sealed record SbomIngestRequest
{
    // Hierarchy (flat — every field serializes inline at the root).
    public required string Client { get; init; }
    public required string Project { get; init; }
    public required string Component { get; init; }
    public string? ComponentKind { get; init; }
    public string? Flavor { get; init; }
    public required string Version { get; init; }
    public string? CommitSha { get; init; }
    public string? Branch { get; init; }
    public string? BuildId { get; init; }
    public string? PullRequestRef { get; init; }

    // SBOM provenance (optional)
    /// <summary>CycloneDX <c>serialNumber</c> (e.g. <c>"urn:uuid:..."</c>).</summary>
    public string? SerialNumber { get; init; }
    /// <summary>CycloneDX spec version the source BOM declared (<c>"1.4"</c>, <c>"1.5"</c>, ...).</summary>
    public string? SpecVersion { get; init; }
    /// <summary>Producing tool short name (e.g. <c>"syft"</c>, <c>"CycloneDX module for .NET"</c>).</summary>
    public string? ToolName { get; init; }
    /// <summary>Producing tool version (e.g. <c>"1.42.0"</c>).</summary>
    public string? ToolVersion { get; init; }
    /// <summary>CycloneDX <c>metadata.tools</c> entries (1.5+ object shape, flattened).</summary>
    public IReadOnlyList<SbomMetadataTool>? MetadataTools { get; init; }

    // Graph (required; arrays may be empty)
    public required IReadOnlyList<SbomComponent> Components { get; init; }
    public required IReadOnlyList<SbomDependency> Dependencies { get; init; }
}

/// <summary>Tool entry from <c>metadata.tools.components[]</c> (CycloneDX 1.5+) or <c>metadata.tools[]</c> (1.4).</summary>
public sealed record SbomMetadataTool
{
    public string? Vendor { get; init; }
    public required string Name { get; init; }
    public string? Version { get; init; }
}

/// <summary>A single component from the SBOM graph (spec v1.2 §2.1).</summary>
public sealed record SbomComponent
{
    /// <summary>Package URL (e.g. <c>"pkg:nuget/Newtonsoft.Json@13.0.1"</c>). Canonical identifier.</summary>
    public required string Purl { get; init; }
    /// <summary>Display name (typically matches the PURL's name segment).</summary>
    public required string Name { get; init; }
    /// <summary>Component version (typically matches the PURL's version segment).</summary>
    public required string Version { get; init; }
    /// <summary>CycloneDX type — <c>"library"</c>, <c>"framework"</c>, <c>"application"</c>, <c>"container"</c>, ....</summary>
    public string? Kind { get; init; }
    /// <summary>SPDX license expression, when known.</summary>
    public string? License { get; init; }
    /// <summary>Per-component vulnerabilities (rare; typically use <c>/sbom-vulnerabilities/upsert</c> instead).</summary>
    public IReadOnlyList<SbomComponentVulnerability>? Vulnerabilities { get; init; }
    /// <summary>Algorithm → hash dict (e.g. <c>{ "SHA-256": "..." }</c>).</summary>
    public IReadOnlyDictionary<string, string>? Hashes { get; init; }
}

/// <summary>Optional per-component vulnerability inlined in the SBOM (preferred path = <c>/sbom-vulnerabilities/upsert</c>).</summary>
public sealed record SbomComponentVulnerability
{
    public required string AdvisoryId { get; init; }
    public required string Severity { get; init; }
    public string? Title { get; init; }
    public string? Description { get; init; }
    public string? ReferenceUrl { get; init; }
}

/// <summary>Edge in the SBOM dependency graph (parent → child PURL).</summary>
public sealed record SbomDependency
{
    public required string ParentPurl { get; init; }
    public required string ChildPurl { get; init; }
}

/// <summary>Response from <c>POST /ingest/sbom</c> (spec v1.2 §2.1).</summary>
public sealed record SbomIngestResponse
{
    /// <summary>Sink-assigned ComponentVersion id (stable across re-ingests of the same hierarchy tuple).</summary>
    public required Guid ComponentVersionId { get; init; }
    /// <summary>Sink-assigned SBOM snapshot id. Pass to <see cref="TampIngestClient.PostSbomProvenanceAsync"/> and <see cref="TampIngestClient.PostSbomVulnerabilitiesUpsertAsync"/>.</summary>
    public required Guid SbomSnapshotId { get; init; }
    public int ComponentsCount { get; init; }
    public int DependenciesCount { get; init; }
    public int VulnerabilitiesCount { get; init; }
}

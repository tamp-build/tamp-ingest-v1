namespace Tamp.Ingest.V1;

/// <summary>
/// Body for <c>POST /ingest/findings</c> (spec v1.2 §2.3). Adopter parses SARIF
/// (or any scanner output) and reshapes to a flat <c>findings[]</c> array.
/// </summary>
/// <remarks>
/// Use <see cref="SarifFindingsMapper.FromSarif"/> to map a <c>Tamp.Sarif.SarifLog</c>
/// into a <see cref="FindingsIngestRequest"/> in one call. <see cref="Scanner"/>
/// is the discriminator the sink uses to attach the right scanner-rule registry.
/// </remarks>
public sealed record FindingsIngestRequest
{
    // Hierarchy (flat)
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

    /// <summary>Who produced this build — agent or human (spec v1.3). Optional; dropped on the wire when absent.</summary>
    public IngestActor? Actor { get; init; }

    /// <summary>The scanner that produced the findings. PascalCase enum on the wire.</summary>
    public required ScannerKind Scanner { get; init; }

    /// <summary>Findings array. May be empty (sink still records the scan-run via /ingest/scan-runs).</summary>
    public required IReadOnlyList<IngestFinding> Findings { get; init; }
}

/// <summary>One flattened finding row in the <see cref="FindingsIngestRequest.Findings"/> array (spec v1.2 §2.3).</summary>
public sealed record IngestFinding
{
    /// <summary>Rule identifier (e.g. <c>"S125"</c>, <c>"AVD-DS-002"</c>, <c>"@typescript-eslint/no-unused-vars"</c>).</summary>
    public required string RuleId { get; init; }

    /// <summary>Severity — Critical / High / Medium / Low / Info (PascalCase).</summary>
    public required Severity Severity { get; init; }

    /// <summary>One-line title (≤ 512 chars enforced sink-side).</summary>
    public required string Title { get; init; }

    /// <summary>Long-form description. Unlimited length.</summary>
    public string? Description { get; init; }

    /// <summary>Relative file path inside the component (≤ 1024 chars enforced sink-side).</summary>
    public string? FilePath { get; init; }

    /// <summary>1-based line number of the finding within <see cref="FilePath"/>.</summary>
    public int? Line { get; init; }

    /// <summary>Optional source snippet for the line.</summary>
    public string? Snippet { get; init; }

    /// <summary>
    /// Sub-category bucket (spec v1.2 §3.5). Splits a single ScannerKind into routable buckets —
    /// <c>"vulnerability"</c>/<c>"misconfiguration"</c>/<c>"secret"</c> for Trivy, <c>"accessibility"</c> for AxeCore.
    /// </summary>
    public string? SubCategory { get; init; }
}

/// <summary>Response from <c>POST /ingest/findings</c> (spec v1.2 §2.3).</summary>
public sealed record FindingsIngestResponse
{
    public required Guid ComponentVersionId { get; init; }
    public int FindingsInserted { get; init; }
    public int FindingsUpdated { get; init; }
    public int FindingsReopened { get; init; }
    public int FindingsClosed { get; init; }
    public int FindingsSuppressed { get; init; }
}

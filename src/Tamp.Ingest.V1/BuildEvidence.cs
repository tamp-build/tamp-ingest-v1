namespace Tamp.Ingest.V1;

/// <summary>
/// The build the sink <strong>resolved</strong> an ingest onto (TFND-266). Every single-build ingest response
/// echoes it as <c>build</c>, and <see cref="TampIngestClient.ReadBuildEvidenceAsync"/> keys on it.
/// </summary>
/// <remarks>
/// Log this instead of what you sent. "I posted commit <c>abc123</c>" and "the sink stored it on commit
/// <c>abc123</c>, flavor <c>release</c>" are different claims, and only the second one is evidence.
/// </remarks>
public sealed record ResolvedBuild
{
    /// <summary>Sink-assigned ComponentVersion id.</summary>
    public required Guid ComponentVersionId { get; init; }
    /// <summary>The version string the build carries.</summary>
    public string VersionString { get; init; } = "";
    /// <summary>The commit the sink resolved the build to, when known.</summary>
    public string? CommitSha { get; init; }
    /// <summary>Build flavor (e.g. <c>release</c>), when set.</summary>
    public string? Flavor { get; init; }
    /// <summary>Branch, when known.</summary>
    public string? Branch { get; init; }
    /// <summary>Pull-request ref, for PR builds.</summary>
    public string? PullRequestRef { get; init; }
    /// <summary>When the sink first created this build.</summary>
    public DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// Response from <c>GET /ingest/builds/{commitSha}</c> (TFND-265): everything the sink holds for one commit,
/// per build context. Returned by <see cref="TampIngestClient.ReadBuildEvidenceAsync"/>.
/// </summary>
/// <remarks>
/// A commit has more than one entry in <see cref="Builds"/> only when it was built in more than one flavor or
/// pull-request context. Within a build, a <c>null</c> section or an empty list means that evidence was
/// <strong>not stored</strong>, which is exactly what a "post, then verify" step checks for.
/// </remarks>
public sealed record BuildEvidenceResponse
{
    /// <summary>Sink-side Project id.</summary>
    public required Guid ProjectId { get; init; }
    /// <summary>Client name.</summary>
    public string Client { get; init; } = "";
    /// <summary>Project name.</summary>
    public string Project { get; init; } = "";
    /// <summary>The full commit sha the lookup resolved (even when a prefix was asked for).</summary>
    public string CommitSha { get; init; } = "";
    /// <summary>One entry per build context (flavor / pull request) of this commit.</summary>
    public IReadOnlyList<BuildEvidence> Builds { get; init; } = Array.Empty<BuildEvidence>();
}

/// <summary>What the sink holds for one build of a commit. <c>null</c> or empty means not stored.</summary>
public sealed record BuildEvidence
{
    /// <summary>The build this evidence belongs to.</summary>
    public required ResolvedBuild Build { get; init; }
    /// <summary>Stored coverage rollup, or <c>null</c>.</summary>
    public CoverageEvidence? Coverage { get; init; }
    /// <summary>Stored test-result rollup, or <c>null</c>.</summary>
    public TestResultsEvidence? TestResults { get; init; }
    /// <summary>Stored SBOM snapshot, or <c>null</c>.</summary>
    public SbomEvidence? Sbom { get; init; }
    /// <summary>Findings per scanner. Empty when none were ingested.</summary>
    public IReadOnlyList<ScannerFindingsEvidence> Findings { get; init; } = Array.Empty<ScannerFindingsEvidence>();
    /// <summary>Scan-run receipts. Empty when none were ingested.</summary>
    public IReadOnlyList<ScanRunEvidence> ScanRuns { get; init; } = Array.Empty<ScanRunEvidence>();
    /// <summary>Attested quality-gate verdict, or <c>null</c>.</summary>
    public QualityGateEvidence? QualityGate { get; init; }
    /// <summary>Container-image identity, or <c>null</c>.</summary>
    public ContainerImageEvidence? ContainerImage { get; init; }
    /// <summary>Analysis-coverage completeness, or <c>null</c>.</summary>
    public AnalysisCoverageEvidence? AnalysisCoverage { get; init; }
    /// <summary>Model token usage for the scan, or <c>null</c>.</summary>
    public ScanUsageEvidence? ScanUsage { get; init; }
    /// <summary>Conformance verdicts stored.</summary>
    public int ConformanceVerdicts { get; init; }
    /// <summary>Diagnostics stored.</summary>
    public int Diagnostics { get; init; }
}

/// <summary>Stored coverage rollup for a build.</summary>
public sealed record CoverageEvidence
{
    public string ToolName { get; init; } = "";
    public string? ToolVersion { get; init; }
    public double SequenceCoverage { get; init; }
    public double BranchCoverage { get; init; }
    public int CoveredSequences { get; init; }
    public int TotalSequences { get; init; }
    public int CoveredBranches { get; init; }
    public int TotalBranches { get; init; }
    public int Modules { get; init; }
    public int SourceFiles { get; init; }
    public int Classes { get; init; }
    public DateTimeOffset IngestedAt { get; init; }
}

/// <summary>Stored test-result rollup for a build.</summary>
public sealed record TestResultsEvidence
{
    public string ToolName { get; init; } = "";
    public string? ToolVersion { get; init; }
    public int Total { get; init; }
    public int Passed { get; init; }
    public int Failed { get; init; }
    public int Skipped { get; init; }
    public int Inconclusive { get; init; }
    public int Suites { get; init; }
    public int Cases { get; init; }
    public DateTimeOffset CompletedAt { get; init; }
    public DateTimeOffset IngestedAt { get; init; }
}

/// <summary>Stored SBOM snapshot for a build.</summary>
public sealed record SbomEvidence
{
    public required Guid SnapshotId { get; init; }
    public string? ToolName { get; init; }
    public string? ToolVersion { get; init; }
    public string? SpecVersion { get; init; }
    public string? SerialNumber { get; init; }
    public int Components { get; init; }
    public int Vulnerabilities { get; init; }
    public string? ProvenanceType { get; init; }
    public bool ProvenanceVerified { get; init; }
    public DateTimeOffset IngestedAt { get; init; }
}

/// <summary>Findings one scanner contributed to a build.</summary>
/// <remarks>
/// <see cref="Scanner"/> is the sink's scanner name as a string, not <see cref="ScannerKind"/>, so a scanner
/// the sink knows and this client does not yet know still reads cleanly.
/// </remarks>
public sealed record ScannerFindingsEvidence
{
    public string Scanner { get; init; } = "";
    public int Total { get; init; }
    public int Open { get; init; }
    /// <summary>Open findings keyed by severity name (e.g. <c>"Critical"</c>).</summary>
    public IReadOnlyDictionary<string, int> OpenBySeverity { get; init; } = new Dictionary<string, int>();
}

/// <summary>A stored scan-run receipt. <see cref="Scanner"/> and <see cref="Status"/> are strings for the same reason as on <see cref="ScannerFindingsEvidence"/>.</summary>
public sealed record ScanRunEvidence
{
    public string Scanner { get; init; } = "";
    public string Status { get; init; } = "";
    public int FindingsCount { get; init; }
    public string? ToolName { get; init; }
    public string? ToolVersion { get; init; }
    public DateTimeOffset CompletedAt { get; init; }
    public DateTimeOffset IngestedAt { get; init; }
}

/// <summary>Attested quality-gate verdict for a build.</summary>
public sealed record QualityGateEvidence
{
    public string Status { get; init; } = "";
    public string? Source { get; init; }
    public string? AnalysisId { get; init; }
    public DateTimeOffset ObservedAt { get; init; }
    public DateTimeOffset IngestedAt { get; init; }
}

/// <summary>Container-image identity for a build.</summary>
public sealed record ContainerImageEvidence
{
    public string Reference { get; init; } = "";
    public string? Digest { get; init; }
    public string? BaseImageReference { get; init; }
    public string? BaseImageDigest { get; init; }
    public DateTimeOffset InspectedAt { get; init; }
}

/// <summary>Analysis-coverage completeness for a build.</summary>
public sealed record AnalysisCoverageEvidence
{
    public int Languages { get; init; }
    public string? GapLanguages { get; init; }
    public DateTimeOffset ObservedAt { get; init; }
    public DateTimeOffset IngestedAt { get; init; }
}

/// <summary>Model token usage for a build's scan.</summary>
public sealed record ScanUsageEvidence
{
    public int Observations { get; init; }
    public long InputTokens { get; init; }
    public long OutputTokens { get; init; }
}

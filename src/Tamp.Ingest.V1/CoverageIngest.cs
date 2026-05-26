namespace Tamp.Ingest.V1;

/// <summary>
/// Body for <c>POST /ingest/coverage</c> (spec v1.2 §2.4). Normalized rollup —
/// adopter transforms OpenCover / cobertura / lcov into this shape.
/// </summary>
public sealed record CoverageIngestRequest
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

    /// <summary>Producing tool name (e.g. <c>"OpenCover"</c>, <c>"vitest@coverage-v8"</c>, <c>"cobertura"</c>).</summary>
    public required string ToolName { get; init; }
    public string? ToolVersion { get; init; }

    /// <summary>UTC instant the coverage report completed.</summary>
    public required DateTimeOffset CompletedAt { get; init; }

    /// <summary>Aggregate sequence (line) coverage percentage in [0, 100].</summary>
    public required decimal SequenceCoverage { get; init; }
    /// <summary>Aggregate branch coverage percentage in [0, 100]. Null when the format doesn't report branches.</summary>
    public decimal? BranchCoverage { get; init; }
    public required int CoveredSequences { get; init; }
    public required int TotalSequences { get; init; }

    /// <summary>Per-module breakdown (assembly / package).</summary>
    public required IReadOnlyList<CoverageModule> Modules { get; init; }

    /// <summary>Optional source-text payload for the coverage source viewer.</summary>
    public IReadOnlyList<CoverageSourceFile>? SourceFiles { get; init; }
}

public sealed record CoverageModule
{
    public required string Name { get; init; }
    public required decimal SequenceCoverage { get; init; }
    public decimal? BranchCoverage { get; init; }
    public required int CoveredSequences { get; init; }
    public required int TotalSequences { get; init; }
    public required IReadOnlyList<CoverageClass> Classes { get; init; }
}

public sealed record CoverageClass
{
    /// <summary>Fully-qualified class name or source-file path (TS/JS).</summary>
    public required string FullName { get; init; }
    public string? SourceFile { get; init; }
    public required decimal SequenceCoverage { get; init; }
    public required int CoveredSequences { get; init; }
    public required int TotalSequences { get; init; }
    /// <summary>1-based line numbers that were visited.</summary>
    public required IReadOnlyList<int> VisitedLines { get; init; }
    /// <summary>1-based line numbers that were NOT visited.</summary>
    public required IReadOnlyList<int> UnvisitedLines { get; init; }
}

public sealed record CoverageSourceFile
{
    public required string RelativePath { get; init; }
    public required string SourceText { get; init; }
}

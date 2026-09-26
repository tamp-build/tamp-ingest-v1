namespace Tamp.Ingest.V1;

/// <summary>
/// Body for <c>POST /ingest/test-results</c> (spec v1.2 §2.5). Normalized rollup —
/// adopter transforms TRX / JUnit XML / vitest reports into this shape.
/// </summary>
public sealed record TestResultsIngestRequest
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

    /// <summary>Producing tool (<c>"VSTest"</c>, <c>"vitest"</c>, <c>"junit"</c>).</summary>
    public required string ToolName { get; init; }
    public string? ToolVersion { get; init; }

    public required DateTimeOffset CompletedAt { get; init; }
    public required int DurationMs { get; init; }

    public required int TotalCount { get; init; }
    public required int PassedCount { get; init; }
    public required int FailedCount { get; init; }
    public required int SkippedCount { get; init; }
    public required int InconclusiveCount { get; init; }

    public required IReadOnlyList<TestSuite> Suites { get; init; }
}

public sealed record TestSuite
{
    public required string AssemblyName { get; init; }
    public required string ClassName { get; init; }
    public required int TotalCount { get; init; }
    public required int PassedCount { get; init; }
    public required int FailedCount { get; init; }
    public required int SkippedCount { get; init; }
    public required int DurationMs { get; init; }
    public required IReadOnlyList<TestCase> Cases { get; init; }
}

public sealed record TestCase
{
    public required string Name { get; init; }
    /// <summary>Outcome — Passed / Failed / Skipped / Inconclusive (PascalCase).</summary>
    public required TestOutcome Outcome { get; init; }
    public required int DurationMs { get; init; }
    public string? ErrorMessage { get; init; }
    public string? ErrorStackTrace { get; init; }
}

/// <summary>Per-case test outcome (spec v1.2 §2.5).</summary>
public enum TestOutcome
{
    Passed = 0,
    Failed,
    Skipped,
    Inconclusive,
}

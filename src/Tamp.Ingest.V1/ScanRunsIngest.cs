namespace Tamp.Ingest.V1;

/// <summary>
/// Body for <c>POST /ingest/scan-runs</c> (spec v1.2 §2.6). Flat hierarchy + receipts[] —
/// no <c>componentVersion</c> wrapper (v1.0 / v1.1 documented one; v1.2 corrected).
/// </summary>
public sealed record ScanRunsIngestRequest
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

    /// <summary>One receipt per scanner that ran (including <see cref="ScanRunStatus.Skipped"/> ones).</summary>
    public required IReadOnlyList<ScanRunReceipt> Receipts { get; init; }
}

/// <summary>One scanner-run receipt (spec v1.2 §2.6).</summary>
public sealed record ScanRunReceipt
{
    public required ScannerKind Scanner { get; init; }
    public required ScanRunStatus Status { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required int FindingsCount { get; init; }
    public string? ToolName { get; init; }
    public string? ToolVersion { get; init; }
    /// <summary>Free-form notes — used to explain Failed/Skipped status.</summary>
    public string? Notes { get; init; }
}

/// <summary>Scan-run lifecycle status (spec v1.2 §3.3).</summary>
public enum ScanRunStatus
{
    /// <summary>Scanner ran to completion; <see cref="ScanRunReceipt.FindingsCount"/> reflects what it emitted (zero or more).</summary>
    Succeeded = 0,
    /// <summary>Scanner crashed, was killed, or exited non-zero on a tool-level error. Receipt is still recorded so dashboards distinguish "ran clean" from "never ran".</summary>
    Failed,
    /// <summary>Scanner intentionally skipped (toolchain not installed, repo opted out, etc.).</summary>
    Skipped,
}

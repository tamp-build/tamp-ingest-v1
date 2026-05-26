using System.Text.Json.Serialization;

namespace Tamp.Ingest.V1;

/// <summary>
/// Aggregate code-coverage rollup for a single build/flavor. Spec §6 (<c>POST /ingest/coverage</c>).
/// </summary>
/// <remarks>
/// Percentages are decimals in <c>[0, 100]</c>. <see cref="LinesCovered"/> /
/// <see cref="LinesTotal"/> (etc.) are the underlying integer counts the
/// percentage was derived from; sinks may recompute and warn on drift.
/// </remarks>
public sealed record CoverageIngestRequestDto
{
    /// <summary>Source format (e.g. <c>"cobertura"</c>, <c>"opencover"</c>, <c>"jacoco"</c>).</summary>
    public required string Format { get; init; }

    /// <summary>Line coverage percentage in [0,100]. Required.</summary>
    public required decimal LinePercent { get; init; }

    /// <summary>Branch coverage percentage in [0,100]. Optional — set when the format reports it.</summary>
    public decimal? BranchPercent { get; init; }

    /// <summary>Lines covered count.</summary>
    public int? LinesCovered { get; init; }

    /// <summary>Total lines instrumented.</summary>
    public int? LinesTotal { get; init; }

    /// <summary>Branches covered count.</summary>
    public int? BranchesCovered { get; init; }

    /// <summary>Total branches instrumented.</summary>
    public int? BranchesTotal { get; init; }

    /// <summary>Optional raw report blob (gzipped + base64) for archival.</summary>
    public string? RawReportGzB64 { get; init; }
}

/// <summary>
/// Aggregate test-result rollup for a single build/flavor. Spec §7 (<c>POST /ingest/test-results</c>).
/// </summary>
public sealed record TestResultsIngestRequestDto
{
    /// <summary>Source format (e.g. <c>"trx"</c>, <c>"junit"</c>, <c>"xunit2"</c>).</summary>
    public required string Format { get; init; }

    /// <summary>Total test cases executed.</summary>
    public required int Total { get; init; }

    /// <summary>Number passing.</summary>
    public required int Passed { get; init; }

    /// <summary>Number failing (asserted vs. error — sinks treat both as red).</summary>
    public required int Failed { get; init; }

    /// <summary>Number skipped / ignored.</summary>
    public required int Skipped { get; init; }

    /// <summary>Wall-clock duration in seconds.</summary>
    public decimal? DurationSeconds { get; init; }

    /// <summary>Optional raw report blob (gzipped + base64) for archival.</summary>
    public string? RawReportGzB64 { get; init; }
}

/// <summary>
/// Receipt for a single scanner run within a security pipeline. Spec §8 (<c>POST /ingest/scan-runs</c>).
/// </summary>
/// <remarks>
/// One receipt per scanner per build. Sinks aggregate receipts into the
/// per-component "last scan" status board. Wraps the same metrics emitted
/// by <c>Tamp.Security.Pipeline</c>'s <c>tamp.security.scan.*</c> meters
/// so consumers get an HTTP-side mirror of the OTel signal without scraping.
/// </remarks>
public sealed record ScanRunReceipt
{
    /// <summary>Scanner that produced this receipt.</summary>
    public required ScannerKind Scanner { get; init; }

    /// <summary>UTC instant the scan started.</summary>
    public required DateTimeOffset StartedUtc { get; init; }

    /// <summary>UTC instant the scan completed.</summary>
    public required DateTimeOffset CompletedUtc { get; init; }

    /// <summary>Exit code from the scanner process. <c>0</c> = clean, <c>1</c> = findings,
    /// <c>≥2</c> = tool failure (per the linter-convention pattern used across Tamp wrappers).</summary>
    public required int ExitCode { get; init; }

    /// <summary>Total findings emitted by this run, irrespective of severity.</summary>
    public required int FindingsTotal { get; init; }

    /// <summary>Findings bucketed by severity. Keys are <see cref="Severity"/> wire values.</summary>
    public IReadOnlyDictionary<string, int>? FindingsBySeverity { get; init; }

    /// <summary>Tool/CLI version reported (e.g. <c>"trufflehog 3.85.1"</c>). Optional.</summary>
    public string? ScannerVersion { get; init; }

    /// <summary>Whether the scan was skipped (toolchain not installed). Captures the no-op leg of skippable security targets.</summary>
    public bool Skipped { get; init; }

    /// <summary>Free-form reason when <see cref="Skipped"/> is true (e.g. <c>"opengrep not on PATH"</c>).</summary>
    public string? SkippedReason { get; init; }
}

/// <summary>
/// A single SBOM-derived vulnerability. Spec §9 (<c>POST /ingest/sbom-vulnerabilities</c>).
/// </summary>
/// <remarks>
/// Used for vulnerability sources that DON'T emit SARIF — Grype / OSV / GHSA
/// rollups. SARIF-emitting scanners route through <see cref="TampIngestClient.PostFindingsAsync"/>
/// instead.
/// </remarks>
public sealed record SbomVulnerability
{
    /// <summary>Vulnerability identifier (e.g. <c>"CVE-2024-12345"</c>, <c>"GHSA-xxxx-xxxx-xxxx"</c>, <c>"OSV-2025-100"</c>).</summary>
    public required string Id { get; init; }

    /// <summary>Affected package PURL (e.g. <c>"pkg:nuget/Newtonsoft.Json@13.0.1"</c>).</summary>
    public required string Purl { get; init; }

    /// <summary>Resolved severity for this finding (vendor advisory or scanner-adjusted).</summary>
    public required Severity Severity { get; init; }

    /// <summary>Optional CVSS v3.x base score in <c>[0.0, 10.0]</c>.</summary>
    public decimal? CvssScore { get; init; }

    /// <summary>Optional CVSS vector string (e.g. <c>"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"</c>).</summary>
    public string? CvssVector { get; init; }

    /// <summary>Optional fix version (when the advisory specifies one).</summary>
    public string? FixVersion { get; init; }

    /// <summary>Source advisory URL.</summary>
    public string? AdvisoryUrl { get; init; }

    /// <summary>Optional short description (one-line; full text lives at <see cref="AdvisoryUrl"/>).</summary>
    public string? Description { get; init; }
}

/// <summary>
/// JSON serializer-source-generation context for the ingest DTOs.
/// Used by <see cref="TampIngestClient"/> to avoid runtime reflection-based
/// serialization (AOT-friendly, smaller cold-start cost).
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Converters = new[] { typeof(JsonStringEnumConverter<Severity>), typeof(JsonStringEnumConverter<ScannerKind>) })]
[JsonSerializable(typeof(CoverageIngestRequestDto))]
[JsonSerializable(typeof(TestResultsIngestRequestDto))]
[JsonSerializable(typeof(ScanRunReceipt))]
[JsonSerializable(typeof(IReadOnlyList<ScanRunReceipt>))]
[JsonSerializable(typeof(SbomVulnerability))]
[JsonSerializable(typeof(IReadOnlyList<SbomVulnerability>))]
internal partial class IngestJsonContext : JsonSerializerContext
{
}

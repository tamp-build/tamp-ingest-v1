namespace Tamp.Ingest.V1;

/// <summary>
/// Canonical severity scale for ingest payloads (scan runs, vulnerabilities).
/// Mirrors the spec's <c>Severity</c> vocabulary.
/// </summary>
/// <remarks>
/// SARIF-emitted findings carry their own per-result level — this enum is
/// for the <em>aggregate</em> severity on a scan-run receipt or for
/// vulnerability records sourced outside SARIF.
/// </remarks>
public enum Severity
{
    /// <summary>Informational — no action required.</summary>
    Info = 0,
    /// <summary>Low — eventually fix.</summary>
    Low,
    /// <summary>Medium — should fix.</summary>
    Medium,
    /// <summary>High — must fix.</summary>
    High,
    /// <summary>Critical — must fix now; usually gates release.</summary>
    Critical,
}

/// <summary>Wire-format helpers for <see cref="Severity"/>.</summary>
public static class SeverityExtensions
{
    /// <summary>
    /// Convert a <see cref="Severity"/> to its lowercased wire value
    /// (e.g. <c>Severity.Critical → "critical"</c>).
    /// </summary>
    public static string ToWire(this Severity severity) => severity switch
    {
        Severity.Info     => "info",
        Severity.Low      => "low",
        Severity.Medium   => "medium",
        Severity.High     => "high",
        Severity.Critical => "critical",
        _                 => severity.ToString().ToLowerInvariant(),
    };
}

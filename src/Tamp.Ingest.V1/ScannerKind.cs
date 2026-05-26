namespace Tamp.Ingest.V1;

/// <summary>
/// Canonical scanner identifiers recognized by the tamp-ingest-v1 contract.
/// Sinks use this discriminator to attach the right scanner-rule registry
/// to a SARIF run (rule descriptions, default severities, deprecation flags, etc.).
/// </summary>
/// <remarks>
/// <para>
/// The wire value is the spec's lowercased / hyphenated member name
/// (see <see cref="ScannerKindExtensions.ToWire"/>).
/// Sinks accept any string but flag <c>Unknown</c> for triage when an
/// unrecognized value arrives — keep this enum in sync with the spec's
/// <c>ScannerKind</c> vocabulary (spec §3.1).
/// </para>
/// <para>
/// Adding a new value here is a non-breaking source change AND a non-breaking wire
/// change: existing sinks will route the new value through their <c>Unknown</c> path
/// until the sink-side vocabulary catches up.
/// </para>
/// </remarks>
public enum ScannerKind
{
    /// <summary>Scanner not classifiable — sink flags for triage.</summary>
    Unknown = 0,

    /// <summary>OpenGrep / Semgrep-compatible static analysis.</summary>
    OpenGrep,

    /// <summary>TruffleHog v3 secret scanning.</summary>
    TruffleHog,

    /// <summary>GitHub CodeQL static analysis.</summary>
    CodeQL,

    /// <summary>Aqua Trivy container / IaC / dependency scanning.</summary>
    Trivy,

    /// <summary>Bridgecrew Checkov IaC scanning.</summary>
    Checkov,

    /// <summary>Aqua tfsec (deprecated upstream, still in active deployment) IaC scanning.</summary>
    Tfsec,

    /// <summary>KICS (Checkmarx) IaC scanning.</summary>
    Kics,

    /// <summary>OWASP ZAP DAST scanning.</summary>
    Zap,

    /// <summary>Stoplight Spectral API contract linting.</summary>
    Spectral,

    /// <summary>oasdiff API contract diff.</summary>
    Oasdiff,

    /// <summary>Sigstore Cosign attestation / signature verification.</summary>
    Cosign,

    /// <summary>NetArchTest .NET architecture rules.</summary>
    NetArchTest,

    /// <summary>dependency-cruiser JS / TS architecture rules.</summary>
    DependencyCruiser,

    /// <summary>Stryker mutation testing.</summary>
    Stryker,

    /// <summary>Coverlet code coverage (when emitted as findings).</summary>
    Coverlet,

    /// <summary>Google osv-scanner (CVE / advisory matching against SBOMs / lockfiles).</summary>
    OsvScanner,

    /// <summary>Anchore Grype dependency vulnerability scanning.</summary>
    Grype,

    /// <summary>Anchore Syft SBOM generation (use this when ingesting Syft-emitted SARIF).</summary>
    Syft,

    /// <summary>Roslyn analyzer / .editorconfig-driven static analysis.</summary>
    Roslyn,

    /// <summary>JetBrains ReSharper / InspectCode static analysis.</summary>
    ReSharper,

    /// <summary>ESLint JS / TS linting.</summary>
    ESLint,

    /// <summary>Deque axe-core accessibility scanning.</summary>
    AxeCore,
}

/// <summary>Wire-format helpers for <see cref="ScannerKind"/>.</summary>
public static class ScannerKindExtensions
{
    /// <summary>
    /// Convert a <see cref="ScannerKind"/> to its lowercased wire value
    /// (e.g. <c>ScannerKind.TruffleHog → "trufflehog"</c>).
    /// </summary>
    public static string ToWire(this ScannerKind kind) => kind switch
    {
        ScannerKind.Unknown            => "unknown",
        ScannerKind.OpenGrep           => "opengrep",
        ScannerKind.TruffleHog         => "trufflehog",
        ScannerKind.CodeQL             => "codeql",
        ScannerKind.Trivy              => "trivy",
        ScannerKind.Checkov            => "checkov",
        ScannerKind.Tfsec              => "tfsec",
        ScannerKind.Kics               => "kics",
        ScannerKind.Zap                => "zap",
        ScannerKind.Spectral           => "spectral",
        ScannerKind.Oasdiff            => "oasdiff",
        ScannerKind.Cosign             => "cosign",
        ScannerKind.NetArchTest        => "netarchtest",
        ScannerKind.DependencyCruiser  => "dependency-cruiser",
        ScannerKind.Stryker            => "stryker",
        ScannerKind.Coverlet           => "coverlet",
        ScannerKind.OsvScanner         => "osv-scanner",
        ScannerKind.Grype              => "grype",
        ScannerKind.Syft               => "syft",
        ScannerKind.Roslyn             => "roslyn",
        ScannerKind.ReSharper          => "resharper",
        ScannerKind.ESLint             => "eslint",
        ScannerKind.AxeCore            => "axe-core",
        _                              => kind.ToString().ToLowerInvariant(),
    };
}

namespace Tamp.Ingest.V1;

/// <summary>
/// The flat hierarchy tuple every <c>/ingest/*</c> body carries inline (spec v1.2 §1).
/// </summary>
/// <remarks>
/// <para>
/// Identical shape across every ingest endpoint — no <c>?clientName=</c> /
/// <c>?versionString=</c> query params. v1.0 / v1.1 of the spec documented
/// query-param hierarchy; v1.2 corrected that to body-inline, which matches
/// the deployed sink.
/// </para>
/// <para>
/// <strong>Required:</strong> <see cref="Client"/>, <see cref="Project"/>,
/// <see cref="Component"/>, <see cref="Version"/>. <see cref="Client"/> must
/// already exist sink-side (it's the bearer-token's scope anchor); Project /
/// Component / Flavor / ComponentVersion are upserted on first ingest.
/// </para>
/// </remarks>
public sealed record IngestHierarchy
{
    /// <summary>Client name — must exist sink-side and match the bearer-token's bound scope.</summary>
    public required string Client { get; init; }

    /// <summary>Project name within the client. Upserted on first ingest.</summary>
    public required string Project { get; init; }

    /// <summary>Component name within the project. Upserted on first ingest.</summary>
    public required string Component { get; init; }

    /// <summary>Component kind — e.g. <c>"solution"</c>, <c>"service"</c>, <c>"library"</c>, <c>"spa"</c>, <c>"function"</c>. Free-form on the wire.</summary>
    public string? ComponentKind { get; init; }

    /// <summary>Flavor axis (e.g. <c>"net10"</c>, <c>"web"</c>). Discriminates multi-target builds.</summary>
    public string? Flavor { get; init; }

    /// <summary>Version string for this ComponentVersion (free-form — SemVer / MinVer / git-tag).</summary>
    public required string Version { get; init; }

    /// <summary>Git commit SHA for the build.</summary>
    public string? CommitSha { get; init; }

    /// <summary>Branch name. <c>main</c> / <c>master</c> are canonical.</summary>
    public string? Branch { get; init; }

    /// <summary>CI vendor's build identifier (e.g. GitHub Actions run id).</summary>
    public string? BuildId { get; init; }

    /// <summary>PR reference. When set, the build is preview-scoped (non-canonical).</summary>
    public string? PullRequestRef { get; init; }
}

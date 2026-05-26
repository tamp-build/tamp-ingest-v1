namespace Tamp.Ingest.V1;

/// <summary>
/// The hierarchy tuple every tamp-ingest-v1 ingest payload identifies itself by.
/// Spec §1 (Hierarchy model).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Required:</strong> <see cref="Client"/>, <see cref="Project"/>,
/// <see cref="Component"/>, <see cref="Version"/>. Sinks upsert missing
/// <see cref="Project"/> / <see cref="Component"/> rows on first ingest.
/// <see cref="Client"/> is enforced against the bearer-token's bound client scope —
/// a <c>cli_</c> token authorizes ingest under any project beneath ONE client.
/// </para>
/// <para>
/// <strong>Optional axes:</strong>
/// </para>
/// <list type="bullet">
///   <item><see cref="Flavor"/> — discriminates multi-target builds (e.g. <c>net8</c>
///         vs <c>net10</c>, <c>Debug</c> vs <c>Release</c>, <c>backend</c> vs <c>web</c>).</item>
///   <item><see cref="CommitSha"/> — git SHA for the build. Surfaces in dashboards
///         alongside the version string.</item>
///   <item><see cref="Branch"/> — <c>main</c> / <c>master</c> are flagged as canonical
///         by the sink; others as non-canonical.</item>
///   <item><see cref="PullRequestRef"/> — when set, the ComponentVersion does NOT
///         count as canonical (build is preview / PR-scoped).</item>
///   <item><see cref="BuildId"/> — CI vendor's build identifier, surfaces on drill-down.</item>
/// </list>
/// </remarks>
public sealed record IngestBuildContext
{
    /// <summary>Client name. Enforced against the bearer-token's bound client scope.</summary>
    public required string Client { get; init; }

    /// <summary>Project name within the client. Sink upserts on first ingest.</summary>
    public required string Project { get; init; }

    /// <summary>Component name within the project. Sink upserts on first ingest.</summary>
    public required string Component { get; init; }

    /// <summary>Version string for this ComponentVersion. Typically a SemVer, MinVer-derived, or git-tag value.</summary>
    public required string Version { get; init; }

    /// <summary>Optional flavor axis (e.g. <c>"net10"</c>, <c>"web"</c>, <c>"backend"</c>).</summary>
    public string? Flavor { get; init; }

    /// <summary>Git commit SHA for the build.</summary>
    public string? CommitSha { get; init; }

    /// <summary>Branch name. <c>main</c> / <c>master</c> are canonical.</summary>
    public string? Branch { get; init; }

    /// <summary>PR reference. When set, the build is preview-scoped and does NOT count as canonical.</summary>
    public string? PullRequestRef { get; init; }

    /// <summary>CI vendor's build identifier (e.g. GitHub Actions run id).</summary>
    public string? BuildId { get; init; }
}

/// <summary>Internal helpers for building the query string from an <see cref="IngestBuildContext"/>.</summary>
internal static class IngestBuildContextExtensions
{
    /// <summary>
    /// Build the standard hierarchy + axis query string for ingest endpoints that consume
    /// the tuple via query params (everything except the snapshot-scoped provenance endpoint).
    /// </summary>
    public static string ToQueryString(this IngestBuildContext ctx)
    {
        if (ctx is null) throw new ArgumentNullException(nameof(ctx));
        if (string.IsNullOrEmpty(ctx.Client)) throw new InvalidOperationException("IngestBuildContext.Client is required.");
        if (string.IsNullOrEmpty(ctx.Project)) throw new InvalidOperationException("IngestBuildContext.Project is required.");
        if (string.IsNullOrEmpty(ctx.Component)) throw new InvalidOperationException("IngestBuildContext.Component is required.");
        if (string.IsNullOrEmpty(ctx.Version)) throw new InvalidOperationException("IngestBuildContext.Version is required.");

        var parts = new List<string>(8)
        {
            $"clientName={Uri.EscapeDataString(ctx.Client)}",
            $"projectName={Uri.EscapeDataString(ctx.Project)}",
            $"componentName={Uri.EscapeDataString(ctx.Component)}",
            $"versionString={Uri.EscapeDataString(ctx.Version)}",
        };
        if (!string.IsNullOrEmpty(ctx.Flavor))         parts.Add($"flavorName={Uri.EscapeDataString(ctx.Flavor!)}");
        if (!string.IsNullOrEmpty(ctx.CommitSha))      parts.Add($"commitSha={Uri.EscapeDataString(ctx.CommitSha!)}");
        if (!string.IsNullOrEmpty(ctx.Branch))         parts.Add($"branchName={Uri.EscapeDataString(ctx.Branch!)}");
        if (!string.IsNullOrEmpty(ctx.PullRequestRef)) parts.Add($"pullRequestRef={Uri.EscapeDataString(ctx.PullRequestRef!)}");
        if (!string.IsNullOrEmpty(ctx.BuildId))        parts.Add($"buildId={Uri.EscapeDataString(ctx.BuildId!)}");

        return string.Join("&", parts);
    }
}

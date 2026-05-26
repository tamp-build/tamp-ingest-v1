using Tamp.Sbom;

namespace Tamp.Ingest.V1;

/// <summary>
/// One-shot reshape of a <see cref="CycloneDxBom"/> into the v1.2-canonical
/// <see cref="SbomIngestRequest"/> shape the sink at <c>/ingest/sbom</c> expects.
/// </summary>
/// <remarks>
/// <para>
/// Decoupled from <see cref="TampIngestClient"/> so adopters can use it à la carte —
/// e.g. to validate the reshape against a fixture before going on the wire, or to
/// archive the normalized DTO to disk during dry runs.
/// </para>
/// <para>
/// <strong>What gets dropped / flattened:</strong>
/// </para>
/// <list type="bullet">
///   <item>CycloneDX <c>metadata.tools</c> is not modeled in <c>Tamp.Sbom</c>'s minimal schema; pass <c>metadataTools</c> explicitly via <see cref="BuildRequest"/> if your sink needs them populated.</item>
///   <item>Multi-license <c>licenses[]</c> is flattened to the first non-null SPDX expression (or the first <c>license.id</c> if no expression).</item>
///   <item><c>hashes[]</c> (algorithm + content) flattens to a dict keyed by algorithm.</item>
///   <item>CycloneDX dependency edges (<c>{ref, dependsOn[]}</c>) are exploded into <c>{parentPurl, childPurl}</c> pairs by resolving <c>bom-ref → purl</c> against the component table. Edges whose ref doesn't resolve are dropped.</item>
///   <item>Top-level <c>vulnerabilities[]</c> from CycloneDX are NOT mapped — use the <c>/sbom-vulnerabilities/upsert</c> endpoint (which keys off snapshotId) instead.</item>
/// </list>
/// </remarks>
public static class CycloneDxSbomMapper
{
    /// <summary>Map the BOM graph (components + dependencies) only, without hierarchy or provenance.</summary>
    public static (IReadOnlyList<SbomComponent> Components, IReadOnlyList<SbomDependency> Dependencies) FromCycloneDx(CycloneDxBom bom)
    {
        if (bom is null) throw new ArgumentNullException(nameof(bom));

        var components = (bom.Components ?? Array.Empty<CycloneDxComponent>())
            .Select(MapComponent)
            .ToList();

        // bom-ref → purl table for dependency-edge resolution.
        var refToPurl = new Dictionary<string, string>(StringComparer.Ordinal);
        if (bom.Components is not null)
        {
            foreach (var c in bom.Components)
            {
                if (!string.IsNullOrEmpty(c.BomRef) && !string.IsNullOrEmpty(c.Purl))
                    refToPurl[c.BomRef] = c.Purl;
            }
        }

        var edges = new List<SbomDependency>();
        if (bom.Dependencies is not null)
        {
            foreach (var edge in bom.Dependencies)
            {
                if (!refToPurl.TryGetValue(edge.Ref ?? "", out var parentPurl)) continue;
                if (edge.DependsOn is null) continue;
                foreach (var childRef in edge.DependsOn)
                {
                    if (!refToPurl.TryGetValue(childRef ?? "", out var childPurl)) continue;
                    edges.Add(new SbomDependency { ParentPurl = parentPurl, ChildPurl = childPurl });
                }
            }
        }

        return (components, edges);
    }

    /// <summary>
    /// One-shot helper: build the complete <see cref="SbomIngestRequest"/> from a BOM
    /// + hierarchy. Optional <paramref name="toolName"/> / <paramref name="toolVersion"/> /
    /// <paramref name="metadataTools"/> override BOM-derived values when supplied.
    /// </summary>
    public static SbomIngestRequest BuildRequest(
        IngestHierarchy hierarchy,
        CycloneDxBom bom,
        string? toolName = null,
        string? toolVersion = null,
        IReadOnlyList<SbomMetadataTool>? metadataTools = null)
    {
        if (hierarchy is null) throw new ArgumentNullException(nameof(hierarchy));
        if (bom is null) throw new ArgumentNullException(nameof(bom));

        var (components, dependencies) = FromCycloneDx(bom);

        return new SbomIngestRequest
        {
            Client = hierarchy.Client,
            Project = hierarchy.Project,
            Component = hierarchy.Component,
            ComponentKind = hierarchy.ComponentKind,
            Flavor = hierarchy.Flavor,
            Version = hierarchy.Version,
            CommitSha = hierarchy.CommitSha,
            Branch = hierarchy.Branch,
            BuildId = hierarchy.BuildId,
            PullRequestRef = hierarchy.PullRequestRef,
            SerialNumber = bom.SerialNumber,
            SpecVersion = bom.SpecVersion,
            ToolName = toolName,
            ToolVersion = toolVersion,
            MetadataTools = metadataTools,
            Components = components,
            Dependencies = dependencies,
        };
    }

    private static SbomComponent MapComponent(CycloneDxComponent c) => new()
    {
        Purl = c.Purl ?? c.BomRef ?? $"{c.Name}@{c.Version}",
        Name = c.Name,
        Version = c.Version ?? "",
        Kind = c.Type,
        License = FlattenLicense(c.Licenses),
        Vulnerabilities = null,
        Hashes = FlattenHashes(c.Hashes),
    };

    private static string? FlattenLicense(IReadOnlyList<CycloneDxLicenseChoice>? licenses)
    {
        if (licenses is null || licenses.Count == 0) return null;
        foreach (var choice in licenses)
        {
            if (!string.IsNullOrEmpty(choice.Expression)) return choice.Expression;
            if (!string.IsNullOrEmpty(choice.License?.Id)) return choice.License!.Id;
            if (!string.IsNullOrEmpty(choice.License?.Name)) return choice.License!.Name;
        }
        return null;
    }

    private static IReadOnlyDictionary<string, string>? FlattenHashes(IReadOnlyList<CycloneDxHash>? hashes)
    {
        if (hashes is null || hashes.Count == 0) return null;
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hashes)
        {
            if (!string.IsNullOrEmpty(h.Alg) && !string.IsNullOrEmpty(h.Content))
                dict[h.Alg] = h.Content;
        }
        return dict.Count == 0 ? null : dict;
    }
}

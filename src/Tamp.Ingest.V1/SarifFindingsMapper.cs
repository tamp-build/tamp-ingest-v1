using Tamp.Sarif;

namespace Tamp.Ingest.V1;

/// <summary>
/// One-shot reshape of a <see cref="SarifLog"/> into the flat <see cref="IngestFinding"/>
/// list the v1.2 <c>/ingest/findings</c> endpoint expects.
/// </summary>
/// <remarks>
/// <para>
/// Decoupled from <see cref="TampIngestClient"/> so adopters can use it à la carte —
/// e.g. for archival, for converting on-disk SARIF to the ingest shape during dry runs,
/// or for unit-testing the reshape independent of any HTTP plumbing.
/// </para>
/// <para>
/// <strong>Severity mapping</strong> (spec v1.2 §3.2):
/// </para>
/// <list type="bullet">
///   <item><see cref="SarifLevel.Error"/>   → <see cref="Severity.High"/></item>
///   <item><see cref="SarifLevel.Warning"/> → <see cref="Severity.Medium"/></item>
///   <item><see cref="SarifLevel.Note"/>    → <see cref="Severity.Low"/></item>
///   <item><see cref="SarifLevel.None"/>    → <see cref="Severity.Info"/></item>
/// </list>
/// <para>
/// <strong>SubCategory</strong> is not auto-extracted — <c>Tamp.Sarif</c>'s
/// minimal model doesn't preserve <c>result.properties.tags</c>. Pass
/// <c>defaultSubCategory</c> when a scanner's findings should all share one
/// bucket (e.g. <c>"accessibility"</c> for AxeCore SARIF; <c>"misconfiguration"</c>
/// for a known-IaC Trivy SARIF). For mixed-bucket SARIF (general Trivy fs scans
/// emitting both vulnerability + misconfiguration + secret), call the sink-side
/// classifier or split the SARIF before mapping.
/// </para>
/// </remarks>
public static class SarifFindingsMapper
{
    /// <summary>
    /// Flatten every <c>runs[*].results[*]</c> in <paramref name="log"/> to an
    /// <see cref="IngestFinding"/> array suitable for <see cref="FindingsIngestRequest.Findings"/>.
    /// </summary>
    public static IReadOnlyList<IngestFinding> FromSarif(SarifLog log, string? defaultSubCategory = null)
    {
        if (log is null) throw new ArgumentNullException(nameof(log));

        var findings = new List<IngestFinding>();
        if (log.Runs is null) return findings;

        foreach (var run in log.Runs)
        {
            if (run?.Results is null) continue;

            foreach (var result in run.Results)
            {
                if (result is null) continue;

                var location = result.Locations?.FirstOrDefault();
                var physical = location?.PhysicalLocation;
                var messageText = result.Message?.Text;

                findings.Add(new IngestFinding
                {
                    RuleId = result.RuleId ?? "<unknown>",
                    Severity = MapLevel(result.Level),
                    Title = TrimTitle(messageText),
                    Description = messageText,
                    FilePath = physical?.ArtifactLocation?.Uri,
                    Line = physical?.Region?.StartLine,
                    Snippet = null,                       // Tamp.Sarif's minimal model doesn't expose snippet
                    SubCategory = defaultSubCategory,
                });
            }
        }

        return findings;
    }

    /// <summary>
    /// One-shot helper: build the complete <see cref="FindingsIngestRequest"/> from a
    /// <see cref="SarifLog"/> + scanner kind + hierarchy.
    /// </summary>
    public static FindingsIngestRequest BuildRequest(
        IngestHierarchy hierarchy,
        ScannerKind scanner,
        SarifLog log,
        string? defaultSubCategory = null)
    {
        if (hierarchy is null) throw new ArgumentNullException(nameof(hierarchy));
        if (log is null) throw new ArgumentNullException(nameof(log));

        return new FindingsIngestRequest
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
            Scanner = scanner,
            Findings = FromSarif(log, defaultSubCategory),
        };
    }

    private static Severity MapLevel(SarifLevel level) => level switch
    {
        SarifLevel.Error   => Severity.High,
        SarifLevel.Warning => Severity.Medium,
        SarifLevel.Note    => Severity.Low,
        SarifLevel.None    => Severity.Info,
        _                  => Severity.Medium,
    };

    // Title is the spec's one-line summary (≤512 chars sink-side).
    private static string TrimTitle(string? message)
    {
        if (string.IsNullOrEmpty(message)) return "<no message>";
        var firstLine = message.Split('\n', 2)[0].TrimEnd('\r').Trim();
        return firstLine.Length > 512 ? firstLine[..512] : firstLine;
    }
}

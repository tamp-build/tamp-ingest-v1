using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tamp.Ingest.V1;

/// <summary>
/// Body for <c>POST /ingest/posture</c> (spec v1.3 §2.8) — repo/org security-posture
/// observations (TAM-290).
/// </summary>
/// <remarks>
/// <para>
/// Posture is a property of the <strong>repository / organisation</strong>, not of a build,
/// so this body carries <strong>no component / version / commit hierarchy</strong> — only
/// <see cref="Client"/>, <see cref="Project"/>, <see cref="Source"/> and the
/// <see cref="Observations"/> set. Authenticate with a project (<c>prj_</c>) token; the
/// <see cref="Client"/> / <see cref="Project"/> must match the token's bound scope.
/// </para>
/// <para>
/// <strong>Report the fact, not a judgement</strong> — findings decides what gates. Post the
/// <strong>full set</strong> of observations every run: a stored observation older than 30 days
/// is treated by the gate as unassessed. Check ids are findings-defined; an unknown
/// <see cref="PostureObservation.CheckId"/> makes the sink reject the <strong>whole batch</strong>
/// with <c>400</c> and the list of known ids — so send every known id, using
/// <see cref="PostureStatus.Unknown"/> for one you could not assess rather than omitting it.
/// </para>
/// </remarks>
public sealed record PostureIngestRequest
{
    /// <summary>Client name — must match the bearer-token's bound scope.</summary>
    public required string Client { get; init; }

    /// <summary>Project name within the client.</summary>
    public required string Project { get; init; }

    /// <summary>Who produced the observations — e.g. <c>"tamp:github"</c>. Defaults to <c>tamp:github</c>.</summary>
    public string Source { get; init; } = "tamp:github";

    /// <summary>The full set of posture observations for this run.</summary>
    public required IReadOnlyList<PostureObservation> Observations { get; init; }
}

/// <summary>One repo/org posture observation (spec v1.3 §2.8).</summary>
public sealed record PostureObservation
{
    /// <summary>findings-defined check id (e.g. <c>branch-protection</c>, <c>org-2fa</c>). An unknown id rejects the whole batch.</summary>
    public required string CheckId { get; init; }

    /// <summary>
    /// The observed fact. The <see cref="JsonConverterAttribute"/> is applied here at the
    /// <strong>property</strong> level (not just on the enum type) because the global
    /// <see cref="JsonStringEnumConverter"/> in <see cref="IngestJsonOptions.Default"/> — being
    /// registered in the options' converter collection — outranks a type-level attribute and would
    /// otherwise emit the PascalCase form. A property-level attribute outranks the collection.
    /// </summary>
    [JsonConverter(typeof(PostureStatusJsonConverter))]
    public required PostureStatus Status { get; init; }

    /// <summary>Optional human-readable evidence for the status (e.g. <c>"force-push blocked; 2 status checks required"</c>).</summary>
    public string? Detail { get; init; }

    /// <summary>When the fact was observed (UTC). Optional — defaults sink-side to now; must never be in the future.</summary>
    public DateTimeOffset? ObservedAt { get; init; }
}

/// <summary>
/// Posture observation outcome (spec v1.3 §3.4). Serializes to the sink's lowercase,
/// hyphenated wire tokens (<c>pass</c> / <c>fail</c> / <c>not-applicable</c> / <c>unknown</c>)
/// via <see cref="PostureStatusJsonConverter"/> — <strong>not</strong> the PascalCase form the
/// shared <see cref="IngestJsonOptions"/> enum converter emits for every other ingest enum.
/// </summary>
[JsonConverter(typeof(PostureStatusJsonConverter))]
public enum PostureStatus
{
    /// <summary>The check is satisfied.</summary>
    Pass,

    /// <summary>The check is not satisfied.</summary>
    Fail,

    /// <summary>The check does not apply to this repo/org (e.g. org-2FA on a user-owned repo).</summary>
    NotApplicable,

    /// <summary>The fact could not be assessed (e.g. the token cannot read it). Report this rather than omitting the observation.</summary>
    Unknown,
}

/// <summary>
/// Maps <see cref="PostureStatus"/> to/from the sink's lowercase-hyphenated wire tokens.
/// Applied at the enum type level so it overrides the global PascalCase
/// <see cref="JsonStringEnumConverter"/> in <see cref="IngestJsonOptions.Default"/>.
/// </summary>
internal sealed class PostureStatusJsonConverter : JsonConverter<PostureStatus>
{
    public override PostureStatus Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => (reader.GetString() ?? "").Trim().ToLowerInvariant() switch
        {
            "pass" => PostureStatus.Pass,
            "fail" => PostureStatus.Fail,
            "not-applicable" or "notapplicable" or "n/a" => PostureStatus.NotApplicable,
            "unknown" => PostureStatus.Unknown,
            var other => throw new JsonException($"Unknown posture status '{other}'."),
        };

    public override void Write(Utf8JsonWriter writer, PostureStatus value, JsonSerializerOptions options)
        => writer.WriteStringValue(value switch
        {
            PostureStatus.Pass => "pass",
            PostureStatus.Fail => "fail",
            PostureStatus.NotApplicable => "not-applicable",
            PostureStatus.Unknown => "unknown",
            _ => throw new JsonException($"Unhandled posture status '{value}'."),
        });
}

namespace Tamp.Ingest.V1;

/// <summary>Whether a build's events/artifacts/ingest were produced by an automated agent or a human (spec v1.3).</summary>
public enum ActorKind
{
    Agent,
    Human,
}

/// <summary>
/// Who produced the build being ingested (spec v1.3 — "attributable by construction", ADR 0019
/// Invariant #4). Carried inline on each <c>/ingest/*</c> hierarchy block alongside
/// <c>buildId</c>/<c>commitSha</c>/<c>branch</c>. Optional and additive: absent on the wire for
/// pre-v1.3 producers (nulls are dropped), so existing payloads are unaffected.
/// </summary>
public sealed record IngestActor
{
    /// <summary>Actor identity — e.g. an agent pool id (<c>pool/3</c>) or a human login/email.</summary>
    public required string Id { get; init; }

    /// <summary>Agent or human.</summary>
    public required ActorKind Kind { get; init; }

    /// <summary>
    /// Map a tamp build <c>workerId</c> (tamp #19: <c>agent:&lt;id&gt;</c> / <c>human:&lt;id&gt;</c>) to an
    /// <see cref="IngestActor"/>. The resolution <em>order</em> is owned build-side; this is the wire
    /// mapping only. An unrecognized / prefix-less value is treated as a human. Returns null for
    /// null/blank input so callers can pass a possibly-absent workerId straight through.
    /// </summary>
    public static IngestActor? FromWorkerId(string? workerId)
    {
        if (string.IsNullOrWhiteSpace(workerId)) return null;
        var value = workerId.Trim();

        var sep = value.IndexOf(':');
        if (sep > 0)
        {
            var prefix = value[..sep];
            var id = value[(sep + 1)..].Trim();
            if (id.Length > 0)
            {
                if (prefix.Equals("agent", StringComparison.OrdinalIgnoreCase))
                    return new IngestActor { Id = id, Kind = ActorKind.Agent };
                if (prefix.Equals("human", StringComparison.OrdinalIgnoreCase))
                    return new IngestActor { Id = id, Kind = ActorKind.Human };
            }
        }

        // No recognized prefix — treat the whole value as a human identity.
        return new IngestActor { Id = value, Kind = ActorKind.Human };
    }
}

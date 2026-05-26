using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tamp.Ingest.V1;

/// <summary>
/// Writes <see cref="DateTimeOffset"/> as <c>yyyy-MM-ddTHH:mm:ssZ</c> when the offset is
/// zero (matching the v1.2 golden fixtures' canonical UTC form), or the default
/// round-trip <c>O</c>-format otherwise. STJ's default emits <c>+00:00</c> for UTC
/// rather than <c>Z</c> — both are valid ISO 8601 but the sink's emit-side uses <c>Z</c>,
/// so we mirror that for round-trip purity.
/// </summary>
internal sealed class UtcCanonicalDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetDateTimeOffset();

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        if (value.Offset == TimeSpan.Zero)
        {
            // Emit "Z" form. Use millisecond precision only when non-zero so 1:30:00.000 → "01:30:00Z" not "01:30:00.000Z".
            var s = value.Millisecond == 0
                ? value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
                : value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
            writer.WriteStringValue(s);
        }
        else
        {
            writer.WriteStringValue(value.ToString("O", CultureInfo.InvariantCulture));
        }
    }
}

/// <summary>
/// Canonical JSON serializer options for tamp-ingest-v1 bodies (spec v1.2).
/// </summary>
/// <remarks>
/// <para>
/// camelCase property names, drop nulls, ISO-8601 timestamps, PascalCase enum
/// values (matches the sink's default <c>JsonStringEnumConverter</c> with no
/// naming-policy override). Hyphenated wire names like <c>"axe-core"</c>
/// (used in <c>ScannerKindExtensions.ToWire</c>) DON'T apply in body
/// serialization — that helper is the legacy URL-encoded form from 0.1.0;
/// the canonical body shape uses the bare PascalCase enum name.
/// </para>
/// </remarks>
public static class IngestJsonOptions
{
    /// <summary>The single <see cref="JsonSerializerOptions"/> the client and all helpers share.</summary>
    public static JsonSerializerOptions Default { get; } = Build();

    private static JsonSerializerOptions Build()
    {
        var o = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
        };
        // PascalCase enum names — matches the sink's default JsonStringEnumConverter.
        o.Converters.Add(new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false));
        // UTC instants emit as "Z" rather than "+00:00" to match the v1.2 golden fixtures.
        o.Converters.Add(new UtcCanonicalDateTimeOffsetConverter());
        return o;
    }
}

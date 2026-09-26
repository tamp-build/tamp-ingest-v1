using System.Text.Json;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// Spec v1.3 actor field: nested <c>actor { id, kind }</c> on the ingest hierarchy, its wire shape,
/// backward-compatible drop-when-absent, and the <c>workerId</c> → actor mapping (tamp #19 glue).
/// </summary>
public sealed class IngestActorTests
{
    private static string FixturePath(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    [Fact]
    public void Actor_RoundTrips_As_Nested_Object_With_PascalCase_Kind()
    {
        var original = File.ReadAllText(FixturePath("12-test-results-with-actor-request.json"));
        var req = JsonSerializer.Deserialize<TestResultsIngestRequest>(original, IngestJsonOptions.Default)!;

        Assert.NotNull(req.Actor);
        Assert.Equal("pool/3", req.Actor!.Id);
        Assert.Equal(ActorKind.Agent, req.Actor.Kind);

        var json = JsonSerializer.Serialize(req, IngestJsonOptions.Default);
        using var doc = JsonDocument.Parse(json);
        var actor = doc.RootElement.GetProperty("actor");
        Assert.Equal("pool/3", actor.GetProperty("id").GetString());
        Assert.Equal("Agent", actor.GetProperty("kind").GetString());   // PascalCase enum on the wire
    }

    [Fact]
    public void Actor_Is_Dropped_On_The_Wire_When_Absent()
    {
        var req = new TestResultsIngestRequest
        {
            Client = "c", Project = "p", Component = "c", Version = "1.0.0",
            ToolName = "VSTest", CompletedAt = DateTimeOffset.UtcNow, DurationMs = 1,
            TotalCount = 0, PassedCount = 0, FailedCount = 0, SkippedCount = 0, InconclusiveCount = 0,
            Suites = System.Array.Empty<TestSuite>(),
        };
        var json = JsonSerializer.Serialize(req, IngestJsonOptions.Default);
        Assert.DoesNotContain("\"actor\"", json);   // additive: pre-v1.3 payloads are byte-unaffected
    }

    [Theory]
    [InlineData("agent:pool/3", "pool/3", ActorKind.Agent)]
    [InlineData("human:scott", "scott", ActorKind.Human)]
    [InlineData("human:scott.singleton@example.com", "scott.singleton@example.com", ActorKind.Human)]
    [InlineData("  agent:runner-7  ", "runner-7", ActorKind.Agent)]
    [InlineData("plainlogin", "plainlogin", ActorKind.Human)]      // no prefix → human
    public void FromWorkerId_Maps_Tamp_WorkerIds(string workerId, string expectedId, ActorKind expectedKind)
    {
        var actor = IngestActor.FromWorkerId(workerId);
        Assert.NotNull(actor);
        Assert.Equal(expectedId, actor!.Id);
        Assert.Equal(expectedKind, actor.Kind);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void FromWorkerId_Returns_Null_For_Blank(string? workerId)
        => Assert.Null(IngestActor.FromWorkerId(workerId));
}

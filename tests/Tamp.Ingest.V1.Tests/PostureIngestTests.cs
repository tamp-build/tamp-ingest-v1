using System.Net;
using System.Text;
using System.Text.Json;
using Tamp;
using Tamp.Ingest.V1;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

/// <summary>
/// Wire-level tests for <see cref="TampIngestClient.PostPostureAsync"/> (spec v1.3 §2.8, TAM-290).
/// Asserts the path, the hierarchy-free body shape (client/project/source/observations — no
/// component/version/commit), and that <see cref="PostureStatus"/> serializes to the sink's
/// lowercase-hyphenated wire tokens rather than the PascalCase form every other ingest enum uses.
/// </summary>
public class PostureIngestTests
{
    private static readonly Uri BaseUri = new("https://sink.example.com/");
    private static readonly Secret Token = new("test-token", "prj_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    private static (TampIngestClient client, CapturingHandler handler) NewClient()
    {
        var handler = new CapturingHandler
        {
            Responder = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            },
        };
        var http = new HttpClient(handler);
        return (new TampIngestClient(BaseUri, Token, http), handler);
    }

    private static PostureIngestRequest SampleRequest() => new()
    {
        Client = "Tamp",
        Project = "tamp-core",
        Observations = new[]
        {
            new PostureObservation { CheckId = "branch-protection", Status = PostureStatus.Pass, Detail = "force-push blocked; 2 status checks required" },
            new PostureObservation { CheckId = "pr-reviews-required", Status = PostureStatus.Pass, Detail = "1 approving review required" },
            new PostureObservation { CheckId = "signed-commits", Status = PostureStatus.Fail, Detail = "not required" },
            new PostureObservation { CheckId = "org-2fa", Status = PostureStatus.NotApplicable, Detail = "user-owned repo" },
            new PostureObservation { CheckId = "codeowners", Status = PostureStatus.Unknown },
        },
    };

    [Fact]
    public async Task PostPosture_UsesIngestPosturePath_NoQueryParams_WithBearer()
    {
        var (client, handler) = NewClient();

        await client.PostPostureAsync(SampleRequest());

        var sent = Assert.Single(handler.Sent);
        Assert.Equal("/ingest/posture", sent.Path);
        Assert.Empty(sent.Query);
        Assert.Equal("application/json", sent.ContentType);
        Assert.Equal("Bearer prj_test_AAAAAAAAAAAAAAAAAAAAAAAAAAAAA", sent.Authorization);
    }

    [Fact]
    public async Task PostPosture_BodyIsHierarchyFree_ClientProjectSourceObservations()
    {
        var (client, handler) = NewClient();

        await client.PostPostureAsync(SampleRequest());

        using var body = JsonDocument.Parse(Assert.Single(handler.Sent).Body!);
        var root = body.RootElement;
        Assert.Equal("Tamp", root.GetProperty("client").GetString());
        Assert.Equal("tamp-core", root.GetProperty("project").GetString());
        Assert.Equal("tamp:github", root.GetProperty("source").GetString());   // defaulted
        Assert.Equal(5, root.GetProperty("observations").GetArrayLength());

        // Posture carries NO build/commit hierarchy — these must be absent.
        Assert.False(root.TryGetProperty("component", out _));
        Assert.False(root.TryGetProperty("version", out _));
        Assert.False(root.TryGetProperty("commitSha", out _));
    }

    [Fact]
    public async Task PostPosture_StatusSerializesToLowercaseHyphenatedWireTokens()
    {
        var (client, handler) = NewClient();

        await client.PostPostureAsync(SampleRequest());

        using var body = JsonDocument.Parse(Assert.Single(handler.Sent).Body!);
        var obs = body.RootElement.GetProperty("observations");
        Assert.Equal("branch-protection", obs[0].GetProperty("checkId").GetString());
        Assert.Equal("pass", obs[0].GetProperty("status").GetString());
        Assert.Equal("fail", obs[2].GetProperty("status").GetString());
        // The one that must NOT regress to the PascalCase "NotApplicable" the global enum converter emits.
        Assert.Equal("not-applicable", obs[3].GetProperty("status").GetString());
        Assert.Equal("unknown", obs[4].GetProperty("status").GetString());
    }

    [Fact]
    public async Task PostPosture_DropsNullDetail_AndOmitsObservedAtWhenUnset()
    {
        var (client, handler) = NewClient();

        await client.PostPostureAsync(SampleRequest());

        using var body = JsonDocument.Parse(Assert.Single(handler.Sent).Body!);
        var obs = body.RootElement.GetProperty("observations");
        Assert.False(obs[4].TryGetProperty("detail", out _));      // codeowners had null detail → dropped
        Assert.False(obs[0].TryGetProperty("observedAt", out _));  // unset → dropped (sink defaults to now)
    }

    [Fact]
    public async Task PostPosture_ObservedAt_EmitsCanonicalZForm()
    {
        var (client, handler) = NewClient();

        await client.PostPostureAsync(new PostureIngestRequest
        {
            Client = "Tamp", Project = "tamp-core",
            Observations = new[]
            {
                new PostureObservation
                {
                    CheckId = "branch-protection", Status = PostureStatus.Pass,
                    ObservedAt = new DateTimeOffset(2026, 10, 29, 7, 0, 0, TimeSpan.Zero),
                },
            },
        });

        using var body = JsonDocument.Parse(Assert.Single(handler.Sent).Body!);
        Assert.Equal("2026-10-29T07:00:00Z",
            body.RootElement.GetProperty("observations")[0].GetProperty("observedAt").GetString());
    }

    [Fact]
    public async Task PostPosture_RoundTripsThroughCanonicalOptions()
    {
        var original = SampleRequest();
        var json = JsonSerializer.Serialize(original, IngestJsonOptions.Default);
        var back = JsonSerializer.Deserialize<PostureIngestRequest>(json, IngestJsonOptions.Default)!;

        Assert.Equal(original.Source, back.Source);
        Assert.Equal(original.Observations.Count, back.Observations.Count);
        Assert.Equal(PostureStatus.NotApplicable, back.Observations[3].Status);
        Assert.Equal(PostureStatus.Unknown, back.Observations[4].Status);
    }

    [Fact]
    public async Task PostPosture_NonSuccess_BubblesApiExceptionWithKnownIds()
    {
        var handler = new CapturingHandler
        {
            Responder = _ => new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent("{\"error\":\"unknown checkId 'foo'; known: branch-protection,...\"}",
                    Encoding.UTF8, "application/json"),
            },
        };
        var client = new TampIngestClient(BaseUri, Token, new HttpClient(handler));

        var ex = await Assert.ThrowsAnyAsync<Tamp.Http.ApiException>(() => client.PostPostureAsync(SampleRequest()));
        Assert.Equal(HttpStatusCode.BadRequest, ex.StatusCode);
        Assert.Contains("unknown checkId", ex.ResponseBody);
    }
}

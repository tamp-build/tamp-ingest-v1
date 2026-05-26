using Bogus;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

public class IngestBuildContextTests
{
    [Fact]
    public void ToQueryString_RequiredOnly_Emits_FourPairs_InCanonicalOrder()
    {
        var ctx = new IngestBuildContext
        {
            Client = "Tamp",
            Project = "tamp",
            Component = "tamp",
            Version = "1.13.0",
        };

        var qs = ctx.ToQueryString();

        Assert.Equal("clientName=Tamp&projectName=tamp&componentName=tamp&versionString=1.13.0", qs);
    }

    [Fact]
    public void ToQueryString_AllAxes_AreEmitted_InCanonicalOrder()
    {
        var ctx = new IngestBuildContext
        {
            Client = "Tamp",
            Project = "tamp",
            Component = "tamp",
            Version = "1.13.0",
            Flavor = "net10",
            CommitSha = "abc123",
            Branch = "main",
            PullRequestRef = "refs/pull/42/head",
            BuildId = "17431",
        };

        var qs = ctx.ToQueryString();

        // Canonical ordering: required tuple first, then optional axes in spec order.
        Assert.Equal(
            "clientName=Tamp&projectName=tamp&componentName=tamp&versionString=1.13.0" +
            "&flavorName=net10&commitSha=abc123&branchName=main" +
            "&pullRequestRef=refs%2Fpull%2F42%2Fhead&buildId=17431",
            qs);
    }

    [Theory]
    [InlineData("Hello World",        "Hello%20World")]
    [InlineData("a+b",                "a%2Bb")]
    [InlineData("a/b",                "a%2Fb")]
    [InlineData("a&b=c",              "a%26b%3Dc")]
    [InlineData("é",                  "%C3%A9")]
    [InlineData("漢",                 "%E6%BC%A2")]
    [InlineData("emoji-🚀",           "emoji-%F0%9F%9A%80")]
    public void ToQueryString_EscapesSpecialCharacters_InClientName(string raw, string expectedEscaped)
    {
        var ctx = new IngestBuildContext
        {
            Client = raw,
            Project = "p",
            Component = "c",
            Version = "1.0.0",
        };

        var qs = ctx.ToQueryString();

        Assert.Contains($"clientName={expectedEscaped}&", qs);
    }

    [Fact]
    public void ToQueryString_Omits_NullOptionalAxes()
    {
        var ctx = new IngestBuildContext
        {
            Client = "c",
            Project = "p",
            Component = "comp",
            Version = "v",
            // All optional axes intentionally null.
        };

        var qs = ctx.ToQueryString();

        Assert.DoesNotContain("flavorName", qs);
        Assert.DoesNotContain("commitSha", qs);
        Assert.DoesNotContain("branchName", qs);
        Assert.DoesNotContain("pullRequestRef", qs);
        Assert.DoesNotContain("buildId", qs);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void ToQueryString_Throws_OnMissingRequiredField(string? value)
    {
        var ctx = new IngestBuildContext
        {
            Client = value!,
            Project = "p",
            Component = "c",
            Version = "v",
        };

        Assert.Throws<InvalidOperationException>(() => ctx.ToQueryString());
    }

    [Fact]
    public void ToQueryString_RoundTripsBoguslyGeneratedInputs_WithoutLosingPairs()
    {
        // Random axis values — verifies escaping doesn't drop or merge query params.
        var faker = new Faker();
        for (var i = 0; i < 25; i++)
        {
            var ctx = new IngestBuildContext
            {
                Client = faker.Random.String2(1, 30),
                Project = faker.Random.String2(1, 30),
                Component = faker.Random.String2(1, 30),
                Version = faker.System.Semver(),
                Flavor = faker.Random.Bool() ? faker.Random.String2(1, 12) : null,
                CommitSha = faker.Random.Hash(40),
                Branch = faker.Random.Bool() ? "main" : faker.Random.String2(1, 20),
                BuildId = faker.Random.Int(1, 1_000_000).ToString(),
            };

            var qs = ctx.ToQueryString();

            // Each pair we emitted should reappear by name.
            Assert.Contains("clientName=", qs);
            Assert.Contains("projectName=", qs);
            Assert.Contains("componentName=", qs);
            Assert.Contains("versionString=", qs);
            Assert.Contains("commitSha=", qs);
            Assert.Contains("branchName=", qs);
            Assert.Contains("buildId=", qs);
            if (ctx.Flavor is not null) Assert.Contains("flavorName=", qs);
        }
    }
}

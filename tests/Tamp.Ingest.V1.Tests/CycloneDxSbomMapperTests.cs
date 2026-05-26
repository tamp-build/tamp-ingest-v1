using Tamp.Sbom;
using Xunit;

namespace Tamp.Ingest.V1.Tests;

public class CycloneDxSbomMapperTests
{
    private static IngestHierarchy SampleHierarchy() => new()
    {
        Client = "BrewingCoder",
        Project = "tamp",
        Component = "tamp",
        Version = "1.13.0",
    };

    [Fact]
    public void FromCycloneDx_Empty_ReturnsEmptyLists()
    {
        var bom = new CycloneDxBom { BomFormat = "CycloneDX", SpecVersion = "1.5", Version = 1 };
        var (components, deps) = CycloneDxSbomMapper.FromCycloneDx(bom);
        Assert.Empty(components);
        Assert.Empty(deps);
    }

    [Fact]
    public void FromCycloneDx_MapsPurlNameVersionKindLicense()
    {
        var bom = new CycloneDxBom
        {
            Components = new[]
            {
                new CycloneDxComponent
                {
                    BomRef = "Foo@1.0.0",
                    Purl = "pkg:nuget/Foo@1.0.0",
                    Name = "Foo",
                    Version = "1.0.0",
                    Type = "library",
                    Licenses = new[] { new CycloneDxLicenseChoice { Expression = "MIT OR Apache-2.0" } },
                },
            },
        };

        var (components, _) = CycloneDxSbomMapper.FromCycloneDx(bom);
        var c = Assert.Single(components);
        Assert.Equal("pkg:nuget/Foo@1.0.0", c.Purl);
        Assert.Equal("Foo", c.Name);
        Assert.Equal("1.0.0", c.Version);
        Assert.Equal("library", c.Kind);
        Assert.Equal("MIT OR Apache-2.0", c.License);
    }

    [Fact]
    public void FromCycloneDx_FallsBackOnLicenseIdWhenNoExpression()
    {
        var bom = new CycloneDxBom
        {
            Components = new[]
            {
                new CycloneDxComponent
                {
                    Purl = "pkg:nuget/Foo@1.0.0", Name = "Foo", Version = "1.0.0",
                    Licenses = new[] { new CycloneDxLicenseChoice { License = new CycloneDxLicense { Id = "MIT" } } },
                },
            },
        };

        var (components, _) = CycloneDxSbomMapper.FromCycloneDx(bom);
        Assert.Equal("MIT", components[0].License);
    }

    [Fact]
    public void FromCycloneDx_FlattensHashesByAlgorithm()
    {
        var bom = new CycloneDxBom
        {
            Components = new[]
            {
                new CycloneDxComponent
                {
                    Purl = "pkg:nuget/Foo@1.0.0", Name = "Foo", Version = "1.0.0",
                    Hashes = new[]
                    {
                        new CycloneDxHash { Alg = "SHA-256", Content = "abc" },
                        new CycloneDxHash { Alg = "SHA-512", Content = "def" },
                    },
                },
            },
        };

        var (components, _) = CycloneDxSbomMapper.FromCycloneDx(bom);
        var hashes = components[0].Hashes!;
        Assert.Equal(2, hashes.Count);
        Assert.Equal("abc", hashes["SHA-256"]);
        Assert.Equal("def", hashes["SHA-512"]);
    }

    [Fact]
    public void FromCycloneDx_ResolvesDependencyEdgesAcrossBomRefs()
    {
        var bom = new CycloneDxBom
        {
            Components = new[]
            {
                new CycloneDxComponent { BomRef = "A", Purl = "pkg:nuget/A@1", Name = "A", Version = "1" },
                new CycloneDxComponent { BomRef = "B", Purl = "pkg:nuget/B@1", Name = "B", Version = "1" },
                new CycloneDxComponent { BomRef = "C", Purl = "pkg:nuget/C@1", Name = "C", Version = "1" },
            },
            Dependencies = new[]
            {
                new CycloneDxDependency { Ref = "A", DependsOn = new[] { "B", "C" } },
            },
        };

        var (_, edges) = CycloneDxSbomMapper.FromCycloneDx(bom);

        Assert.Equal(2, edges.Count);
        Assert.Contains(edges, e => e.ParentPurl == "pkg:nuget/A@1" && e.ChildPurl == "pkg:nuget/B@1");
        Assert.Contains(edges, e => e.ParentPurl == "pkg:nuget/A@1" && e.ChildPurl == "pkg:nuget/C@1");
    }

    [Fact]
    public void FromCycloneDx_DropsEdgesWithUnresolvableRefs()
    {
        var bom = new CycloneDxBom
        {
            Components = new[]
            {
                new CycloneDxComponent { BomRef = "A", Purl = "pkg:nuget/A@1", Name = "A", Version = "1" },
            },
            Dependencies = new[]
            {
                new CycloneDxDependency { Ref = "A", DependsOn = new[] { "X-not-in-components" } },
                new CycloneDxDependency { Ref = "Y-not-in-components", DependsOn = new[] { "A" } },
            },
        };

        var (_, edges) = CycloneDxSbomMapper.FromCycloneDx(bom);
        Assert.Empty(edges);
    }

    [Fact]
    public void BuildRequest_CopiesHierarchyAndProvenanceFields()
    {
        var hierarchy = SampleHierarchy() with { Flavor = "net10", CommitSha = "abc123" };
        var bom = new CycloneDxBom { SerialNumber = "urn:uuid:test", SpecVersion = "1.5" };
        var tools = new[] { new SbomMetadataTool { Vendor = "v", Name = "n", Version = "1.0" } };

        var req = CycloneDxSbomMapper.BuildRequest(hierarchy, bom, toolName: "syft", toolVersion: "1.42.0", metadataTools: tools);

        Assert.Equal("BrewingCoder", req.Client);
        Assert.Equal("net10", req.Flavor);
        Assert.Equal("abc123", req.CommitSha);
        Assert.Equal("urn:uuid:test", req.SerialNumber);
        Assert.Equal("1.5", req.SpecVersion);
        Assert.Equal("syft", req.ToolName);
        Assert.Same(tools, req.MetadataTools);
    }

    [Fact]
    public void BuildRequest_NullArgumentsThrow()
    {
        var bom = new CycloneDxBom();
        Assert.Throws<ArgumentNullException>(() => CycloneDxSbomMapper.BuildRequest(null!, bom));
        Assert.Throws<ArgumentNullException>(() => CycloneDxSbomMapper.BuildRequest(SampleHierarchy(), null!));
    }
}

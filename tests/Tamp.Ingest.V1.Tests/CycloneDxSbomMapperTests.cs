using System.Linq;
using System.Text.Json;
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

    // ---- #8: dev/build-only marking (devDependency) ----

    private static CycloneDxBom TwoComponentBom() => new()
    {
        Components = new[]
        {
            new CycloneDxComponent { BomRef = "Lib@1.0.0", Purl = "pkg:nuget/Lib@1.0.0", Name = "Lib", Version = "1.0.0", Type = "library" },
            new CycloneDxComponent { BomRef = "xunit@2.9.2", Purl = "pkg:nuget/xunit@2.9.2", Name = "xunit", Version = "2.9.2", Type = "library" },
        },
    };

    [Fact]
    public void DevDependency_IsNull_WhenNoClassifierGiven()
    {
        var (components, _) = CycloneDxSbomMapper.FromCycloneDx(TwoComponentBom());
        Assert.All(components, c => Assert.Null(c.DevDependency));
    }

    [Fact]
    public void DevDependency_IsSetExplicitly_ForEveryComponent_WhenClassifierGiven()
    {
        // Producer classifier: anything named like a test package is dev, everything else ships.
        var (components, _) = CycloneDxSbomMapper.FromCycloneDx(
            TwoComponentBom(), c => c.Name.StartsWith("xunit", System.StringComparison.OrdinalIgnoreCase));

        var lib = components.Single(c => c.Name == "Lib");
        var xunit = components.Single(c => c.Name == "xunit");
        Assert.False(lib.DevDependency);   // explicit false (shipping) — not null
        Assert.True(xunit.DevDependency);  // explicit true (dev-only)
    }

    [Fact]
    public void DevDependency_SerializesCamelCase_AndOmitsWhenNull()
    {
        var (withClassifier, _) = CycloneDxSbomMapper.FromCycloneDx(
            TwoComponentBom(), c => c.Name == "xunit");
        var json = JsonSerializer.Serialize(withClassifier, IngestJsonOptions.Default);
        Assert.Contains("\"devDependency\":true", json);
        Assert.Contains("\"devDependency\":false", json);

        var (noClassifier, _) = CycloneDxSbomMapper.FromCycloneDx(TwoComponentBom());
        var jsonNull = JsonSerializer.Serialize(noClassifier, IngestJsonOptions.Default);
        Assert.DoesNotContain("devDependency", jsonNull); // omitted (WhenWritingNull)
    }

    [Fact]
    public void BuildRequest_PassesClassifierThrough()
    {
        var req = CycloneDxSbomMapper.BuildRequest(
            SampleHierarchy(), TwoComponentBom(), isDevDependency: c => c.Name == "xunit");
        Assert.True(req.Components.Single(c => c.Name == "xunit").DevDependency);
        Assert.False(req.Components.Single(c => c.Name == "Lib").DevDependency);
    }
}

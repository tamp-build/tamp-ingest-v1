# Tamp.Ingest.V1

> Typed C# client + DTOs for the `tamp-ingest-v1` egress contract — the canonical wire shape every Tamp-driven build pushes to a compliant sink (tamp.findings, DefectDojo bridge, evidence vault, …).

| Package | Status |
|---|---|
| `Tamp.Ingest.V1` | 0.2.0 — aligned with v1.2 spec + golden fixtures |

> **0.2.0 is a breaking rewrite.** Pre-0.2.0 wire shapes were built against spec v1.0/v1.1, which v1.2 retracted; the deployed sink never accepted them. See [CHANGELOG](CHANGELOG.md#020--unreleased) for migration notes. 0.1.x callers must update.

## Install

```bash
dotnet add package Tamp.Ingest.V1
```

Multi-targets net8 / net9 / net10. Depends on `Tamp.Http` (auth + base HTTP client), `Tamp.Sarif` (typed SARIF model), `Tamp.Sbom` (CycloneDX type graph). The SARIF + SBOM models are inputs to the mapper helpers — the sink itself doesn't speak raw SARIF / CycloneDX, it speaks normalized DTOs that the mappers reshape into.

## When to use this

Use `Tamp.Ingest.V1` when your build needs to push findings / SBOMs / coverage / test results / scan-run telemetry to **any** sink that speaks the `tamp-ingest-v1` contract. The first server-side consumer is [tamp.findings](https://github.com/tamp-build/tamp-findings); any compliant sink (your own, a partner's, an enterprise pipeline bridge) plugs in by accepting the same shapes.

The Tamp framework itself does **not** import this package — the contract is independent of the framework, so adopters who reject `Tamp.Build` can still ship to a `tamp-ingest-v1`-speaking sink from any .NET build path.

## Quick start

```csharp
using Tamp;
using Tamp.Ingest.V1;
using Tamp.Sarif;
using Tamp.Sbom;

// One client per build, one bearer token (cli_… or prj_…).
using var ingest = new TampIngestClient(
    new Uri("https://tamp-findings.brewingcoder.com"),
    new Secret("ingest-token", Environment.GetEnvironmentVariable("TAMP_INGEST_TOKEN")!));

// The hierarchy tuple identifies every payload below. Same shape across every endpoint.
var hierarchy = new IngestHierarchy
{
    Client = "Tamp",
    Project = "tamp",
    Component = "tamp",
    ComponentKind = "solution",
    Flavor = "net10",
    Version = "1.13.0",
    CommitSha = Environment.GetEnvironmentVariable("GITHUB_SHA"),
    Branch = Environment.GetEnvironmentVariable("GITHUB_REF_NAME"),
    BuildId = Environment.GetEnvironmentVariable("GITHUB_RUN_ID"),
};

// 1. Push the SBOM (the sink stores it as a snapshot; you get the snapshot id back).
var bom = SbomReader.LoadFromFile("artifacts/security/tamp.cdx.json");
var sbomResponse = await ingest.PostSbomAsync(hierarchy, bom, toolName: "syft", toolVersion: "1.42.0");

// 2. Push SARIF findings per scanner — the typed client maps SARIF to the flat findings[] shape.
var sarif = SarifReader.LoadFromFile("artifacts/security/opengrep.sarif");
await ingest.PostFindingsAsync(hierarchy, ScannerKind.OpenGrep, sarif);

// 3. Push scan-run receipts (so the sink can render "ran clean" vs "never ran").
await ingest.PostScanRunsAsync(new ScanRunsIngestRequest
{
    Client = hierarchy.Client, Project = hierarchy.Project, Component = hierarchy.Component,
    ComponentKind = hierarchy.ComponentKind, Flavor = hierarchy.Flavor, Version = hierarchy.Version,
    CommitSha = hierarchy.CommitSha, Branch = hierarchy.Branch,
    Receipts = new[]
    {
        new ScanRunReceipt
        {
            Scanner = ScannerKind.OpenGrep, Status = ScanRunStatus.Succeeded,
            StartedAt = startedUtc, CompletedAt = DateTimeOffset.UtcNow,
            FindingsCount = 0, ToolName = "opengrep", ToolVersion = "1.22.0",
        },
    },
});

// 4. (Optional) Stream OSV-Scanner vulns against the SBOM snapshot you just pushed.
await ingest.PostSbomVulnerabilitiesUpsertAsync(new SbomVulnerabilitiesUpsertRequest
{
    SnapshotId = sbomResponse.SbomSnapshotId,
    Vulnerabilities = osvVulns.Select(v => new SbomVulnerability { /* ... */ }).ToArray(),
});
```

## Endpoint surface

Every endpoint takes the flat hierarchy tuple inline in the body. No query params anywhere.

| Method | HTTP | Path | Body root |
|---|---|---|---|
| `PostSbomAsync` | POST | `/ingest/sbom` | `SbomIngestRequest` (hierarchy + `components[]` + `dependencies[]`) → `SbomIngestResponse` |
| `PostSbomProvenanceAsync` | POST | `/ingest/sbom-snapshots/{snapshotId}/provenance` | Raw SLSA / in-toto / DSSE provenance JSON |
| `PostFindingsAsync` | POST | `/ingest/findings` | `FindingsIngestRequest` (hierarchy + `scanner` + `findings[]`) → `FindingsIngestResponse` |
| `PostCoverageAsync` | POST | `/ingest/coverage` | `CoverageIngestRequest` (hierarchy + `modules[].classes[]` tree) |
| `PostTestResultsAsync` | POST | `/ingest/test-results` | `TestResultsIngestRequest` (hierarchy + `suites[].cases[]` tree) |
| `PostScanRunsAsync` | POST | `/ingest/scan-runs` | `ScanRunsIngestRequest` (hierarchy + `receipts[]`) |
| `PostSbomVulnerabilitiesUpsertAsync` | POST | `/sbom-vulnerabilities/upsert` *(no `/ingest/` prefix)* | `SbomVulnerabilitiesUpsertRequest` (`snapshotId` + `vulnerabilities[]`) → `SbomVulnerabilitiesUpsertResponse` |

## Mapper helpers

The sink doesn't speak raw SARIF or raw CycloneDX. Two static mapper helpers do the reshape:

- **`CycloneDxSbomMapper`** — `FromCycloneDx(bom)` returns `(components[], dependencies[])`; `BuildRequest(hierarchy, bom, toolName?, toolVersion?, metadataTools?)` returns a complete `SbomIngestRequest`. Resolves CycloneDX `bom-ref → purl` dependency edges; flattens multi-license `licenses[]` to the first non-null SPDX expression; flattens `hashes[]` to a `{algorithm: content}` dict.
- **`SarifFindingsMapper`** — `FromSarif(log, defaultSubCategory?)` returns the flat `IngestFinding[]`; `BuildRequest(hierarchy, scanner, log, defaultSubCategory?)` returns a complete `FindingsIngestRequest`. Maps SARIF `level` (`error/warning/note/none`) → `Severity` (`High/Medium/Low/Info`). Trims `title` to first line + ≤ 512 chars.

Both mappers are testable independent of the HTTP client, so you can validate the reshape against an on-disk fixture before going on the wire.

## The hierarchy tuple

```
Client → Project → Component → ComponentVersion
                                  └── Flavor (optional, e.g. net10 / web / backend)
```

- `Client` must already exist sink-side — it's the bearer-token's scope anchor, not auto-created. `cli_…` tokens authorize ingest under any project beneath ONE client (token's `client` field must match the body's). `prj_…` tokens are project-scoped.
- `Project` / `Component` / `Flavor` / `ComponentVersion` are upserted on first ingest.
- `Branch = main` / `master` is canonical; others non-canonical.
- `PullRequestRef` set ⇒ the build is preview-scoped (non-canonical).

## Wire-shape canon

- All bodies serialize via `IngestJsonOptions.Default`: camelCase property names, drop-nulls, PascalCase string enums, UTC `Z` timestamps (matches the v1.2 golden fixtures).
- `Severity`, `ScannerKind`, `ScanRunStatus`, `TestOutcome` all emit as bare PascalCase enum names (e.g. `"Roslyn"`, `"Succeeded"`, `"High"`).
- Round-trip tested against all 11 golden fixtures at <https://github.com/tamp-build/tamp-findings/tree/main/tests/Fixtures/Ingest/v1>.

## Auth

```csharp
var token = new Secret("ingest-token", Environment.GetEnvironmentVariable("TAMP_INGEST_TOKEN")!);
using var ingest = new TampIngestClient(baseUri, token);
```

Auth is always bearer, wrapped in `Tamp.Secret` so the token never lands in process listings, log output, or `ToString` calls (the `TAMP004` analyzer flags any `Reveal()` outside the framework's approved boundary).

## Error handling

Failed responses surface as `Tamp.Http.ApiException`:

- 4xx → `Tamp.Http.ApiClientException` (caller fault; don't retry without changing the request)
- 5xx → `Tamp.Http.ApiServerException` (`IsTransient == true`; safe to retry with backoff)

Response body is captured on `ResponseBody` (truncated above `MaxCapturedErrorBodyBytes`, default 16 KiB). Sink emits RFC 9457 `application/problem+json` on framework-level rejections; validator-level 400s return a JSON string body.

## Adopter pattern — wiring into a Build.cs

```csharp
Target Ingest => _ => _
    .DependsOn(nameof(Security))   // SARIF + SBOM files already on disk
    .Requires(() => IngestToken != null)
    .Executes(async () =>
    {
        using var ingest = new TampIngestClient(IngestBaseUri, IngestToken);
        var hierarchy = new IngestHierarchy
        {
            Client = "MyClient", Project = "my-project", Component = ComponentName,
            ComponentKind = "solution", Flavor = NetFlavor, Version = GitVersion.NuGetVersionV2,
            CommitSha = Git.Commit, Branch = Git.Branch,
            BuildId = Environment.GetEnvironmentVariable("GITHUB_RUN_ID"),
        };

        var bom = SbomReader.LoadFromFile(SecuritySbomFile);
        var sbomResp = await ingest.PostSbomAsync(hierarchy, bom);

        foreach (var sarifPath in (Artifacts / "security").GlobFiles("*.sarif"))
        {
            var scanner = ResolveScannerFromFileName(sarifPath);
            var log = SarifReader.LoadFromFile(sarifPath);
            await ingest.PostFindingsAsync(hierarchy, scanner, log);
        }
        await ingest.PostScanRunsAsync(BuildReceiptsRequest(hierarchy));
    });
```

Make the target skippable when `IngestToken` is null — the contract is opt-in per build, and local dev should not be forced to push.

## License

MIT — see [LICENSE](LICENSE).

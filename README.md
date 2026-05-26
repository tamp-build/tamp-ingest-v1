# Tamp.Ingest.V1

> Typed C# client + DTOs for the `tamp-ingest-v1` egress contract — the canonical wire shape every Tamp-driven build pushes to a compliant sink (tamp.findings, DefectDojo bridge, evidence vault, …).

| Package | Status |
|---|---|
| `Tamp.Ingest.V1` | 0.1.0 (initial) |

## Install

```bash
dotnet add package Tamp.Ingest.V1
```

Multi-targets net8 / net9 / net10. Pulls in `Tamp.Http` (auth + base HTTP client), `Tamp.Sarif` (findings type graph), and `Tamp.Sbom` (CycloneDX type graph) — the latter two so SARIF + SBOM bodies serialize via the canonical writers rather than the base client's generic JSON path.

## When to use this

Use `Tamp.Ingest.V1` when your build needs to push findings / SBOMs / coverage / test results / scan-run telemetry to **any** sink that speaks the `tamp-ingest-v1` contract. The first server-side consumer is [tamp.findings](https://github.com/tamp-build/tamp-findings); any compliant sink (your own, a partner's, an enterprise pipeline bridge) plugs in by accepting the same shapes.

The Tamp framework itself does **not** import this package — the contract is independent of the framework, so adopters who reject `Tamp.Build` can still ship to a `tamp-ingest-v1`-speaking sink from any .NET build path.

## Quick start

```csharp
using Tamp;
using Tamp.Ingest.V1;
using Tamp.Sarif;

// One client per build, one bearer token (cli_… or prj_…).
using var ingest = new TampIngestClient(
    new Uri("https://tamp-findings.brewingcoder.com"),
    new Secret("ingest-token", Environment.GetEnvironmentVariable("TAMP_INGEST_TOKEN")!));

// The hierarchy tuple identifies every payload below.
var ctx = new IngestBuildContext
{
    Client = "Tamp",
    Project = "tamp",
    Component = "tamp",
    Version = "1.13.0",
    Flavor = "net10",
    CommitSha = Environment.GetEnvironmentVariable("GITHUB_SHA"),
    Branch = Environment.GetEnvironmentVariable("GITHUB_REF_NAME"),
    BuildId = Environment.GetEnvironmentVariable("GITHUB_RUN_ID"),
};

// Push a SARIF file produced by a scanner (e.g. Tamp.OpenGrep / Tamp.Trivy).
var sarif = SarifReader.ReadFromFile("artifacts/security/opengrep.sarif");
await ingest.PostFindingsAsync(ctx, ScannerKind.OpenGrep, sarif);

// Push the aggregate coverage rollup.
await ingest.PostCoverageAsync(ctx, new CoverageIngestRequestDto
{
    Format = "cobertura",
    LinePercent = 87.3m,
    BranchPercent = 71.2m,
});

// Push the per-scanner receipt set so the sink's "last scan" board stays current.
await ingest.PostScanRunsAsync(ctx, new[]
{
    new ScanRunReceipt
    {
        Scanner = ScannerKind.OpenGrep,
        StartedUtc = startedUtc,
        CompletedUtc = DateTimeOffset.UtcNow,
        ExitCode = 0,
        FindingsTotal = 0,
    },
});
```

## Endpoint surface

Every method takes an `IngestBuildContext` (encoded as query params; `clientName` / `projectName` / `componentName` / `versionString` plus optional `flavorName` / `commitSha` / `branchName` / `pullRequestRef` / `buildId`) — except the snapshot-scoped provenance endpoint.

| Method | HTTP | Path | Body |
|---|---|---|---|
| `PostSbomAsync` | POST | `/ingest/sbom` | CycloneDX BOM (via `SbomWriter`) → returns `SbomSnapshotResponse` |
| `PostSbomProvenanceAsync` | POST | `/ingest/sbom/{snapshotId}/provenance` | raw SLSA / in-toto provenance JSON |
| `PostFindingsAsync` | POST | `/ingest/findings` | SARIF 2.1.0 (via `SarifWriter`); adds `&scannerKind=<kind>` |
| `PostCoverageAsync` | POST | `/ingest/coverage` | `CoverageIngestRequestDto` |
| `PostTestResultsAsync` | POST | `/ingest/test-results` | `TestResultsIngestRequestDto` |
| `PostScanRunsAsync` | POST | `/ingest/scan-runs` | `IReadOnlyList<ScanRunReceipt>` (no-op when empty) |
| `PostSbomVulnerabilitiesAsync` | POST | `/ingest/sbom-vulnerabilities` | `IReadOnlyList<SbomVulnerability>` (no-op when empty) |

`POST` collection endpoints are intentionally no-op on empty input — caller doesn't need to guard.

## The hierarchy tuple

```
Client → Project → Component → ComponentVersion
                                  └── Flavor (optional, e.g. net10 / web / backend)
```

- `Client` is enforced against the bearer token's bound client scope. A `cli_` token authorizes ingest under any project beneath ONE client; a `prj_` token is project-scoped.
- `Project` / `Component` are upserted on first ingest — no out-of-band registration needed.
- `Branch` = `main` / `master` is treated as canonical by sinks; others as non-canonical.
- `PullRequestRef` set ⇒ the build is preview-scoped and does NOT count as canonical.

## Bodies: how serialization works

- **SARIF / SBOM** bodies are produced by `SarifWriter.Serialize(log)` / `SbomWriter.Serialize(bom)` and shipped as pre-formed JSON. This preserves the case-sensitive wire shape both standards require (e.g. SARIF's `$schema`, lowercase property names).
- **All other DTOs** (coverage, test-results, scan-runs, sbom-vulnerabilities) serialize via the inherited `TampApiClient` JSON path: camelCase property names, `null` values dropped. `Severity` / `ScannerKind` enums serialize as strings.

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

The response body is captured and exposed on `ResponseBody` (truncated above `MaxCapturedErrorBodyBytes`, default 16 KiB).

## Adopter pattern — wiring into a Build.cs

```csharp
Target Ingest => _ => _
    .DependsOn(nameof(Security))   // SARIF + scan-run files already on disk
    .Requires(() => IngestToken != null)
    .Executes(async () =>
    {
        using var ingest = new TampIngestClient(IngestBaseUri, IngestToken);
        var ctx = new IngestBuildContext
        {
            Client = "MyClient", Project = "my-project",
            Component = ComponentName, Version = GitVersion.NuGetVersionV2,
            Flavor = NetFlavor, CommitSha = Git.Commit,
            Branch = Git.Branch, BuildId = Environment.GetEnvironmentVariable("GITHUB_RUN_ID"),
        };

        foreach (var sarif in (Artifacts / "security").GlobFiles("*.sarif"))
        {
            var scanner = ResolveScannerFromFileName(sarif);
            await ingest.PostFindingsAsync(ctx, scanner, SarifReader.ReadFromFile(sarif));
        }
        await ingest.PostScanRunsAsync(ctx, LoadReceipts());
    });
```

Make the target skippable when `IngestToken` is null — the contract is opt-in per build, and local dev should not be forced to push.

## License

MIT — see [LICENSE](LICENSE).

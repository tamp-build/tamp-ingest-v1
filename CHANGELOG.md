# Changelog

All notable changes to `Tamp.Ingest.V1` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — Unreleased

### Changed — BREAKING

Full rewrite of every endpoint to match the v1.2 spec republish and the 11 golden fixtures committed to `tamp-build/tamp-findings` at `tests/Fixtures/Ingest/v1/`. Pre-0.2.0 wire shape was based on spec v1.0/v1.1 which v1.2 retracted; the deployed sink never accepted those shapes. **0.1.x callers won't deserialize successfully against any live tamp.findings instance** — every endpoint changed paths, query-vs-body, or body shape. See migration notes below.

- **Hierarchy is now flat-inline in every `/ingest/*` body.** No `?clientName=` / `?versionString=` / `?scanner=` query params anywhere. New `IngestHierarchy` record carries the tuple; per-endpoint request records spread it at the root.
- **`/ingest/sbom` accepts the normalized `SbomIngestRequest`**, not raw CycloneDX. Adopters wrap their `CycloneDxBom` via the new `CycloneDxSbomMapper.BuildRequest(hierarchy, bom, …)`. Returns `SbomIngestResponse` with `componentVersionId` + `sbomSnapshotId` + counts.
- **`/ingest/findings` accepts a flat `findings[]` array via `FindingsIngestRequest`** with `scanner` in the body. Adopters reshape SARIF via the new `SarifFindingsMapper.BuildRequest(hierarchy, scanner, log, defaultSubCategory)`. Returns `FindingsIngestResponse` with insert/update/reopen/close/suppress counts. SARIF→findings severity mapping is `error→High / warning→Medium / note→Low / none→Info`.
- **`/sbom-vulnerabilities/upsert` keys off `snapshotId`** (returned by `/ingest/sbom`), not the hierarchy tuple. Note the path: **no `/ingest/` prefix**. New `SbomVulnerabilitiesUpsertRequest`/`Response` records. Adopters pair the SBOM POST with this in the same build step so the snapshot id is in hand.
- **`/ingest/scan-runs` body is flat** — `receipts[]` at the root, no `componentVersion: {…}` wrapper. New `ScanRunStatus` enum (`Succeeded / Failed / Skipped`) replaces the prior exit-code field. New `ScanRunReceipt` fields: `scanner`, `status`, `startedAt`, `completedAt`, `findingsCount`, `toolName`, `toolVersion`, `notes`.
- **`/ingest/coverage` is a rich normalized DTO** — `modules[].classes[]` tree with per-class `visitedLines[]` / `unvisitedLines[]`, optional `sourceFiles[]` for the coverage viewer. Replaces the thin 0.1.x `CoverageIngestRequestDto`.
- **`/ingest/test-results` is a rich normalized DTO** — `suites[].cases[]` tree with per-case `outcome` (Passed / Failed / Skipped / Inconclusive), `errorMessage`, `errorStackTrace`. Replaces the thin 0.1.x `TestResultsIngestRequestDto`.
- **`/ingest/sbom-snapshots/{id}/provenance`** — path corrected from 0.1.x's `/ingest/sbom/{id}/provenance` (404 against the live sink).
- **Wire enums are PascalCase** (matches sink's default `JsonStringEnumConverter`). `ScannerKindExtensions.ToWire()` (lowercase / hyphenated, from 0.1.x) is preserved for the legacy URL-form callers but isn't used by the new body-style endpoints.
- **`DateTimeOffset` UTC instants emit as `2026-05-26T01:30:00Z`**, not `+00:00` — matches the v1.2 golden fixtures.
- **Removed:** `IngestBuildContext` record (now `IngestHierarchy`), `CoverageIngestRequestDto`, `TestResultsIngestRequestDto`, the 0.1.x `ScanRunReceipt`, `SbomVulnerability`, `SbomSnapshotResponse`. All replaced with v1.2-aligned types under per-endpoint files.

### Added

- 75 unit + integration tests across net8 / net9 / net10:
  - 11 fixture round-trip tests asserting the typed DTOs deserialize the golden fixtures and re-serialize structurally-equal JSON (null-tolerant on the original side, since fixtures explicitly spell out `"buildId": null` for documentation).
  - `CycloneDxSbomMapperTests` covers empty BOM, license flattening (expression / id / name), hash flattening, dependency-edge resolution across `bom-ref → purl`, drop-on-unresolvable.
  - `SarifFindingsMapperTests` covers level→severity mapping, title trimming (≤ 512 + first-line-only), null-rule-id / null-message fallbacks, default-sub-category broadcast, multi-run flatten ordering.
  - `TampIngestClientTests` covers every endpoint's path + method + auth + body shape + enum casing + decimal/UTC serialization + error mapping.
- `IngestJsonOptions.Default` — canonical serializer settings (camelCase, drop-nulls, PascalCase string enums, UTC-Z timestamps). Shared by the client and both mappers.

### Migration from 0.1.x

```csharp
// 0.1.x
var ctx = new IngestBuildContext { Client = "c", Project = "p", Component = "comp", Version = "v" };
await client.PostSbomAsync(ctx, cycloneDxBom);
await client.PostFindingsAsync(ctx, ScannerKind.Roslyn, sarifLog);

// 0.2.0
var hierarchy = new IngestHierarchy { Client = "c", Project = "p", Component = "comp", Version = "v" };
var sbomResponse = await client.PostSbomAsync(hierarchy, cycloneDxBom);                   // returns SbomIngestResponse
await client.PostFindingsAsync(hierarchy, ScannerKind.Roslyn, sarifLog);                  // returns FindingsIngestResponse

// New /sbom-vulnerabilities/upsert flow (keys off the SbomSnapshotId)
await client.PostSbomVulnerabilitiesUpsertAsync(new SbomVulnerabilitiesUpsertRequest
{
    SnapshotId = sbomResponse.SbomSnapshotId,
    Vulnerabilities = vulns,
});
```

### Why

Second-adopter integration (the tamp framework's own build) surfaced that the 0.1.x wire shape — built against the published spec v1.0/v1.1 — didn't match the deployed sink at `tamp-findings.brewingcoder.com`. Each request returned 400 (empty body, since fixed sink-side via ProblemDetails). tamp.findings then published v1.2 + 11 golden fixtures drawn from production traffic. 0.2.0 is the catch-up release that brings the typed client into alignment with the actual sink. Going forward, tamp.findings generates the spec straight from `Tamp.Findings.Api/Contracts/*.cs` (TFND-46), eliminating this drift class.

## [0.1.1] — 2026-05-26

### Added

- `ScannerKind` expanded from 11 → 23 values to match the full spec §3.1 vocabulary (v1.1): added `Checkov`, `Tfsec`, `Kics`, `Zap`, `Spectral`, `Oasdiff`, `Cosign`, `NetArchTest`, `DependencyCruiser`, `Stryker`, `Coverlet`, `OsvScanner`. Wire values match the spec exactly (`netarchtest`, `dependency-cruiser`, `osv-scanner`, etc.). Purely additive; existing 0.1.0 callers are unaffected.
- Tripwire test asserting the enum's wire-value set equals the spec's canonical list — drift now fails CI rather than silently mis-routing findings to `Unknown` sink-side.

### Why

Second-adopter integration (tamp framework itself) surfaced that the enum I shipped at 0.1.0 covered fewer than half the spec's scanner vocabulary. Until 0.1.1, calls using e.g. `Tamp.OsvScanner.V2`-emitted SARIF had to be tagged `ScannerKind.Unknown` and lose attribution sink-side. 0.1.1 closes that gap without disturbing any 0.1.0 call shape.

## [0.1.0] — 2026-05-26

### Added

- Initial release. Typed C# client + DTOs for the `tamp-ingest-v1` egress contract:
  - `TampIngestClient` derives from `Tamp.Http.TampApiClient` (auth + base HTTP plumbing) and exposes one async method per ingest endpoint: `PostSbomAsync`, `PostSbomProvenanceAsync`, `PostFindingsAsync`, `PostCoverageAsync`, `PostTestResultsAsync`, `PostScanRunsAsync`, `PostSbomVulnerabilitiesAsync`.
  - `IngestBuildContext` record carries the hierarchy tuple (`Client` → `Project` → `Component` → `Version`) plus optional axes (`Flavor`, `CommitSha`, `Branch`, `PullRequestRef`, `BuildId`). Renders as the canonical query string every endpoint expects.
  - `ScannerKind` enum mirrors the spec's canonical scanner vocabulary (Unknown / OpenGrep / TruffleHog / CodeQL / Trivy / Grype / Syft / Roslyn / ReSharper / ESLint / AxeCore). New values are non-breaking — sinks route unknowns through their `Unknown` path.
  - `Severity` enum (Info / Low / Medium / High / Critical) for scan-run + vulnerability rollups.
  - DTOs: `CoverageIngestRequestDto`, `TestResultsIngestRequestDto`, `ScanRunReceipt`, `SbomVulnerability`, `SbomSnapshotResponse`.
  - SARIF + SBOM bodies serialize via `SarifWriter.Serialize` / `SbomWriter.Serialize` so the canonical case-sensitive wire shape is preserved. Other DTOs use the base client's camelCase + drop-nulls serializer.
  - Collection endpoints (`/ingest/scan-runs`, `/ingest/sbom-vulnerabilities`) are no-op on empty input — caller doesn't need to guard.
  - Auth always bearer, wrapped in `Tamp.Secret` (`TAMP004`-friendly; never leaked to logs / process listings).
- 48 unit tests across net8 / net9 / net10 covering query-string canonical ordering + escaping, scanner / severity enum wire mappings, per-endpoint method + path + body + auth, error mapping (`ApiClientException` 4xx / `ApiServerException` 5xx with captured body), empty-collection no-op behavior, and cancellation propagation.

### Why

The Tamp framework intentionally does not bundle its ingest contract — sinks beyond tamp.findings (DefectDojo bridge, enterprise pipeline ingestors, third-party dashboards) should be reachable from any .NET build path, not just `Tamp.Build`-driven ones. `Tamp.Ingest.V1` is the typed adapter for any caller that wants to speak the contract without re-deriving wire shapes from the spec.

### Closes

- TAM-274 / TAM-275 (sink-side rollup of Tamp.Security.Pipeline metrics) — server-side consumers can now reach via this typed client.

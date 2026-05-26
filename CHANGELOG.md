# Changelog

All notable changes to `Tamp.Ingest.V1` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — Unreleased

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

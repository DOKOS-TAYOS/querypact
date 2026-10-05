# ADR 0001: .NET solution architecture

- **Status:** Accepted
- **Date:** 2026-07-24

## Context

QueryPact verifies agent-proposed PostgreSQL SQL and migrations locally, returns PASS/FAIL/REVIEW/DENY attestations, and must not expose real rows. One primary executable, fail-closed security, open-source under MIT for project-authored code.

## Decision

### Runtime and language

- Target: `net10.0` (.NET 10), C# 14.
- Single host: `Sav.Host` publishes as `querypact.exe`.
- No Python, Node, Java, or Rust as a second runtime for the MVP.
- Native C/C++ only as encapsulated `libpg_query` binaries loaded by the chosen .NET wrapper (ADR 0002).
- Rust stays out of MVP. A future isolated native module would need its own ADR with a real benchmark.
- No ORM (including EF Core).
- No web UI, RAG, local models, multi-database, BI, plugin marketplace, or autonomous production execution in MVP.
- Native AOT, vendor-hosted services are outside the current project scope.

### Product RID

MVP ships `win-x64` only. `linux-x64` is CI / parser-spike evidence, not a supported operator RID. A later packaging ADR can add Linux if we want it as product.

### Domain exception

`Sav.Domain/Serialization/CanonicalJson.cs` may use `System.Text.Json` for deterministic hashing. Nothing else from infra belongs in Domain.

### Host mode

`Sav:Mode` = `AnalyzeOnly` | `Full`.

- AnalyzeOnly: may omit HMAC; must not register attestation get / verify / store.
- Full: requires HMAC at startup (≥32 decoded bytes from env with mandatory `base64:` or `hex:` prefix; unprefixed/opaque UTF-8 → `attestation_hmac_key_invalid_encoding`).

Analyze and Full DI profiles are separate paths.

### Layering notes

- Alias / DSN resolution does not open a live connection by itself; the first PostgreSQL I/O happens when opening a read-only session.
- RO hardening (panic / trigger / pool) must land before plan / catalog / oracle depend on sessions.
- A real alias must already open with `transaction_read_only=on`; the guard observes that state before the DML canary, and the retained verification session then starts its own explicit `BEGIN READ ONLY` transaction.
- `IRedactor` lives in Application; first production implementation is `MinimalStrictRedactor`, later `StrictRedactor` / `PostgresErrorRedactor`.
- Application signs/verifies only via `IAttestationMac`; production impl is `AttestationHmac` in Storage. Key ≥32 bytes from a prefixed env var only.
- Application uses ports (`IConfigPathResolver`, `ITargetAliasResolver`, `IReadOnlySessionFactory` → `IReadOnlySession`, etc.) and passes the pipeline-opened session into catalog / plan / oracle / `ISchemaFingerprintGuard`. Use cases never take infra concretes.

### Solution layout

Same tree as `docs/product/01_ARCHITECTURE.md`:

```text
QueryPact.sln
├── Directory.Build.props
├── Directory.Packages.props
├── global.json
├── build/NativeLibPgQuery.props
├── .editorconfig
├── .gitignore
├── src/
│   ├── Sav.Domain/
│   ├── Sav.Application/
│   ├── Sav.Infrastructure.Config/
│   ├── Sav.Infrastructure.Storage/
│   ├── Sav.Infrastructure.Postgres/
│   └── Sav.Host/
└── tests/
    ├── Sav.Domain.Tests/
    ├── Sav.Application.Tests/
    ├── Sav.Infrastructure.Config.Tests/
    ├── Sav.Infrastructure.Storage.Tests/
    ├── Sav.Infrastructure.Postgres.Tests/
    ├── Sav.Security.Tests/
    └── Sav.Host.Tests/
```

### Project responsibilities

| Project | Allowed deps | Responsibility |
| --- | --- | --- |
| `Sav.Domain` | BCL only | Contracts, IR, decisions, properties, attestations, error codes |
| `Sav.Application` | `Sav.Domain` | Use cases and ports. No YamlDotNet. No unrelated extension ports in the core application |
| `Sav.Infrastructure.Config` | App, Domain, YamlDotNet | YAML loaders + `YamlPolicyEngine` |
| `Sav.Infrastructure.Storage` | App, Domain | File attestation store; `AttestationHmac`; no Npgsql |
| `Sav.Infrastructure.Postgres` | App, Domain, Npgsql, Testcontainers, parser package | Parser, targets, EXPLAIN, catalog, properties, shadow DB, PG redaction |
| `Sav.Host` | All above + System.CommandLine + MCP SDK | CLI, MCP stdio, DI, config, logging, version |

### NuGet stack

| Area | Choice |
| --- | --- |
| PostgreSQL | Npgsql |
| CLI | System.CommandLine |
| YAML | YamlDotNet |
| JSON | System.Text.Json |
| MCP | Official MCP SDK for C# |
| Integration tests | Testcontainers for .NET |
| Unit/integration | xUnit |
| Parser | `pgsqlparser` (ADR 0002) |

### Host and publication

- Binary name: `querypact` / `querypact.exe`.
- Primary publish: self-contained single-file `win-x64`. Multi-file (`SQL-capable-degraded`) only if ADR 0002 recorded packaging profile 2.

```powershell
dotnet publish src/Sav.Host/Sav.Host.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true
```

- Shared MSBuild fragment: `build/NativeLibPgQuery.props` (spike hosts, Postgres infra, Host).
- `linux-x64` remains spike/CI only until a packaging ADR says otherwise.

### Plan provider

`IPlanProvider.GetEstimatedPlanAsync` takes `PolicyDecision`, `Policy`, and `IReadOnlySession?`, returns `PlanGateResult`. On Deny/Review: no EXPLAIN, session may be null. On Allow: use the pipeline session; do not open another one.

Pipeline short-circuits: first policy Deny/Review/unparsable → no session; after Allow → one session → catalog → second policy Deny/Review → skip plan/oracle; after second Allow → fingerprint baseline → plan; plan Deny/Review → skip oracle; plan Allow → fingerprint again → oracle. `ISchemaFingerprintGuard` owns fingerprints.

### Redaction

Once Npgsql is in play, production code uses a real redactor (`MinimalStrictRedactor`, later `StrictRedactor` / `PostgresErrorRedactor`). Pass-through redactors are not allowed under `src/`. If the DML canary INSERT succeeds and rollback cannot be confirmed: fail closed (`ro_canary_rollback_unconfirmed`), mark alias unsafe, dispose the pool.

### Quality defaults

- Nullable reference types; warnings as errors
- Central Package Management
- Deterministic builds; analyzers on; no preview packages without a new ADR
- Every I/O / long-running API takes `CancellationToken`
- Immutable records for contracts and results
- Explicit interfaces at boundaries; no service locator; no mutable global state
- No empty catch blocks; do not swallow cancellation

### Security constraints

- PostgreSQL only in MVP
- Targets by alias; DSNs from env or protected local config
- Zero writes against real target aliases; migrations only on ephemeral PostgreSQL
- Zero real rows in responses / strict logs / attestations; exact cardinalities and EXPLAIN literals are sensitive under `DisclosureProfile`
- Fail closed on unparsable / unsupported / ambiguous SQL
- No regex as primary parser; no MCP `execute_sql`; no default `EXPLAIN ANALYZE`
- All external output crosses the redaction boundary
- App controls complement native PG privileges; they do not replace them
- MVP “review” means policy `review` → attestation `REVIEW`, not human-in-the-loop approval
- `IRedactor.RedactObject<T>` returns a new instance; never mutates inputs
- RO proof: DML canary on `sav_ro_probe` + `SET TRANSACTION READ ONLY` (TEMP/DDL-only canaries are not enough)
- Artifact classes: `stub` | `SQL-capable` | `SQL-capable-degraded` (`docs/release/windows-querypact-verification.md`)
- On conflict: accepted ADRs and shipped code win over product prose

## Consequences

### Positive

- Clear layering; Config/Storage separated from Postgres
- One deliverable (`querypact.exe`)
- Ports leave room for future extensions without loading arbitrary DLLs

### Trade-offs

- Native `libpg_query` complicates single-file packaging
- Testcontainers needs Docker for integration / migration tests
- win-x64-first delays Linux as a product artifact

### Rejected alternatives

| Alternative | Why not |
| --- | --- |
| Multi-executable CLI + MCP daemon | Single-process MVP; smaller confused-deputy surface |
| EF Core / Dapper-as-ORM | Out of scope; direct Npgsql keeps SQL and permissions explicit |
| Python sidecar for parsing | Second runtime |
| Native AOT in MVP | Dep compatibility unproven |
| Web UI host | Out of MVP |
| `YamlPolicyEngine` inside Postgres infra | Wrong layer |
| Pass-through redactor on live PG paths | Zero-leakage from day one |

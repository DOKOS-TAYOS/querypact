# ADR 0002: PostgreSQL parser spike (`pgsqlparser` vs `PostgresQuery`)

- **Status:** Accepted. Chosen package: `pgsqlparser` 1.0.0, packaging profile `1`
- **Date:** 2026-07-24 (method); 2026-07-25 (Chosen from spike evidence)

## Context

PostgreSQL grammar is not something you handle safely with regex. QueryPact needs a real parser that yields a stable IR for authorization, fingerprinting, and fail-closed decisions. Architecture points at a `libpg_query`-based .NET wrapper. Two candidates at planning time: `pgsqlparser` and `PostgresQuery`.

Native binaries are fine when encapsulated inside the chosen NuGet. A second language runtime for parsing is out.

## Decision

### What we ran

Before wiring a production analyzer:

1. Isolated spike under `spikes/parser-comparison/`: BCL + each candidate in separate projects. Both packages evaluated on parse/IR/license cases P01-P12 and P15. Results in `spikes/parser-comparison/results/matrix.md` and `matrix.json`.
2. Both spike hosts import `build/NativeLibPgQuery.props` (same props Host and Postgres infra use) so spike publish settings match production.
3. Packaging profile 1 + P13 (win-x64 single-file post-extract). Props refined accordingly.
4. If profile 1 failed for an otherwise-winning wrapper, evaluate profile 2. Document P14 (linux-x64 spike/CI). Record exactly one Chosen package + packaging profile, or declare both insufficient and open ADR 0004.

Until Chosen + packaging profile are recorded, do not claim SQL-capable. Spike budget was about 15 business days; without a go, default to stub-only. ADR 0004 is the contingency if we pursue a third wrapper after a stop.

### Go / no-go outcomes

| Outcome | Action |
| --- | --- |
| One winner passes P01-P15 on profile 1 | Chosen + profile 1 → intended class `SQL-capable` |
| Winner passes parse/matrix but profile 1 fails; profile 2 loads native + P01-P11 | Chosen + profile 2 → `SQL-capable-degraded`. Single-file stays the preferred goal later |
| Both fail profiles 1 and 2 | Stop SQL verify/analyze features; record dual-fail; open ADR 0004 within ~5 business days only if pursuing a third wrapper. Stub `querypact.exe` for help/version may remain |
| License disqualifies both | Same stop |

No SQL-capable `querypact.exe` without a recorded Chosen package and packaging profile. Any Windows executable verification remains a later maintainer step; see `docs/release/windows-querypact-verification.md`.

### Packaging matrix

| Profile | Layout | Role |
| --- | --- | --- |
| 1 | Self-contained single-file + `IncludeNativeLibrariesForSelfExtract=true` | Primary product objective |
| 2 | Self-contained multi-file | Typed fallback `SQL-capable-degraded`: only if profile 1 fails for the winner |
| 3 | Framework-dependent + native probe | Spike/diagnostics only: cannot alone authorize product |

### Evaluation cases

| Case | Input | Pass criterion |
| --- | --- | --- |
| P01 | Simple `SELECT` | Parse success; statement type Select; tables/columns extracted |
| P02 | CTE (`WITH`) | Parse success; CTE names and referenced tables in IR |
| P03 | Subquery | Nested relation reads visible to policy mapping |
| P04 | `INSERT` | Write target identified |
| P05 | `UPDATE` | Write target + predicate presence |
| P06 | `DELETE` | Write target + predicate presence |
| P07 | DDL | DDL statement types classified |
| P08 | Multiple statements | Detected as multi-statement (must not silently keep only first) |
| P09 | Invalid SQL | Fail closed with structured error |
| P10 | Normalization | Equivalent whitespace/case variants share normalized form |
| P11 | Fingerprint | Stable SHA-256 over normalized form |
| P12 | `net10.0` restore/build | Succeeds with .NET 10 SDK |
| P13 | win-x64 single-file publish of spike host | Native loads after self-extract; P01-P11 still pass |
| P14 | linux-x64 self-contained publish | Native loads; P01-P09 pass. Spike/CI evidence only: not a product RID |
| P15 | License and maintenance | Redistribution-safe; activity/release notes inspected; native provenance documented |

### Scoring

| Outcome | Rule |
| --- | --- |
| Winner | Passes all of P01-P15 on profile 1, or (if profile 1 fails) P01-P12 + P15 + native load on profile 2 with P14 documented |
| Tie | Prefer fewer native load failures across win/linux; then clearer multi-statement detection and fingerprint stability; prefer profile 1 over 2 |
| Both fail | No production parser; write ADR 0004 |

### Production adapter contract

```csharp
namespace Sav.Application.Abstractions;

public interface ISqlParser
{
    // CancellationToken is best-effort for native wrappers that cannot cancel mid-parse.
    // Host analyze paths also apply an independent timeout around Parse.
    SqlParseResult Parse(string sql, CancellationToken cancellationToken);
}

public sealed record SqlParseResult(
    bool Success,
    SqlIr? Ir,
    string? ErrorCode,
    string? RedactedMessage);
```

Canonical home: `src/Sav.Application/Abstractions/SqlParseResult.cs` alongside `ISqlParser.cs`. Do not duplicate under Domain.

`SqlIr` fields for parse/analyze live in Domain / Application contracts. External egress and persisted attestations use `StructuralSqlIr` / `AttestationAnalysis` without `NormalizedSql`.

### Native validation timeline

| Stage | What it proved |
| --- | --- |
| Spike candidates | Parse/IR/license under `dotnet run`/build; no packaging go yet |
| Profile 1 (P13) | Native load after single-file self-extract. Candidate that only works under `dotnet run` fails profile 1 |
| Chosen record | Exactly one package + profile (or dual-fail stop) |
| Production smoke | Publish Host/Infrastructure with the same props / same recorded profile; P01 loads |
| Release smoke | Published `querypact.exe` runs P01 via `querypact analyze` and Full-mode `verify-query` from the Chosen-profile publish directory |

### Spike non-goals

- No policy engine, EXPLAIN, MCP, or oracle in the spike
- No PostgreSQL connection during the spike
- Spike stays under `spikes/`; production consumes only the chosen package via `Sav.Infrastructure.Postgres`

## Consequences

### Positive

- Evidence before locking a security-critical dependency
- Shared props keep spike and Host packaging aligned
- Early production-shaped smoke reduces late single-file failures

### Trade-offs

- Production analyzer waits on Chosen + packaging profile (or ADR 0004 after dual-fail)
- Native binaries need MSBuild beyond `PublishSingleFile=true` alone
- Profile 2 ships multiple files beside `querypact.exe`; operators must keep the publish directory intact

### Single-file native packaging (Chosen)

Locked for `pgsqlparser` profile 1:

```xml
<PropertyGroup>
  <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
</PropertyGroup>
```

No extra winner-specific `ItemGroup` was needed for P13. See `build/NativeLibPgQuery.props`.

### Host publish (must match recorded profile)

**Profile 1:**

```powershell
dotnet publish src/Sav.Host/Sav.Host.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true
```

**Profile 2 (degraded fallback only):**

```powershell
dotnet publish src/Sav.Host/Sav.Host.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=false
```

### Rejected alternatives

| Alternative | Why not |
| --- | --- |
| Regex / hand-rolled tokenizer as primary parser | Forbidden by the security model |
| Defer spike until after policies | Policies without a real parser give false confidence |
| Python `pglast` sidecar | Second runtime |
| Pick a wrapper without matrix evidence | No evidence, no lock |
| Spike-only native validation until release | Leaves a packaging gap; production smoke closes it |
| Divergent spike csproj publish flags vs Host | Shared `build/NativeLibPgQuery.props` required |

## Chosen package

**`pgsqlparser` 1.0.0, packaging profile `1`** (self-contained single-file + `IncludeNativeLibrariesForSelfExtract=true`).

Evidence:

- Matrix: `spikes/parser-comparison/results/matrix.md` / `matrix.json` (P13 win-x64 single-file PASS for Chosen)
- License notes: `spikes/parser-comparison/results/license-notes.md`
- P14 linux-x64: `spikes/parser-comparison/results/p14-linux-x64.json`

`PostgresQuery` 0.1.4 also passed P01-P15 on profile 1, but lost the tie-break (structured `Result` errors, Deparse, 1.0.0 maturity, Windows packaging confidence).

Product go for SQL-capable also needs later native smoke on the same profile and publish smokes. This ADR records the package/profile decision from the spike.

### Evidence retention

Disposable spike host source is not kept in the normalized repo. Retained corpus, matrix, P14, license notes, and package versions are documented in [`spikes/parser-comparison/README.md`](../../spikes/parser-comparison/README.md). The matrix is archival evidence, not a locally rerunnable test project. Production parsing lives in `src/Sav.Infrastructure.Postgres/Parsing/`.

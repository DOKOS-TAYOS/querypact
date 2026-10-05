# Parser comparison matrix (P01-P15)

Date: 2026-07-25
Hosts: disposable `Spike.PgsqlParserHost` (`pgsqlparser` 1.0.0), disposable `Spike.PostgresQueryHost` (`PostgresQuery` 0.1.4)
Corpus: `spikes/parser-comparison/corpus/adversarial.sql` + `Spike.Shared.Corpus`
Shared props: `build/NativeLibPgQuery.props` (`IncludeNativeLibrariesForSelfExtract=true`)

Evidence retention: see [`spikes/parser-comparison/README.md`](../README.md). The
host source is not retained in this checkout; this matrix is archival evidence,
not a locally rerunnable test project.

## Decision

**Chosen package: `pgsqlparser` 1.0.0, packaging profile `1` (win-x64 self-contained single-file).**
Both candidates passed parse/matrix and profile-1 native load. Tie-break: clearer fail-closed `Result` errors, Deparse, 1.0.0 maturity, stronger Windows packaging signal vs PostgresQuery's "Windows untested" README warning.

## Parse / IR cases (dotnet test / host `--case`)

| Case | Criterion | pgsqlparser | PostgresQuery |
| --- | --- | --- | --- |
| P01 Select | parse + tables/columns | PASS | PASS |
| P02 CTE | CTE names + tables | PASS | PASS |
| P03 Subquery | nested reads | PASS | PASS |
| P04 INSERT | write target | PASS | PASS |
| P05 UPDATE | write + predicate | PASS | PASS |
| P06 DELETE | write + predicate | PASS | PASS |
| P07 DDL | create/alter/drop types | PASS | PASS |
| P08 Multi-statement | not silently first-only | PASS | PASS |
| P09 Invalid SQL | fail-closed structured | PASS (`Result.Error`) | PASS (caught exception → `parse_error`) |
| P10 Normalization | shared canonical form | PASS (deparse / native-fp fallback) | PASS (native-fp fallback; Normalize alone does not collapse whitespace) |
| P11 Fingerprint | stable SHA-256 over canonical + literal-insensitive native fp | PASS | PASS |
| P12 net10.0 | restore/build | PASS | PASS |

## Packaging

| Case | Layout | pgsqlparser | PostgresQuery |
| --- | --- | --- | --- |
| P13 | win-x64 self-contained **single-file** + `IncludeNativeLibrariesForSelfExtract=true` | PASS (publish 0, P01 run 0) | PASS (publish 0, P01 run 0) |
| Profile 2 | win-x64 self-contained multi-file | PASS (evidence only; not needed) | PASS (evidence only; not needed) |
| P14 | linux-x64 self-contained single-file (WSL run) | PASS P01-P11 (`DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` for missing WSL libicu) | PASS P01-P11 (same ICU env note) |
| P15 | license/maintenance/natives | PASS (MIT) | PASS (BSD-3-Clause) |

Evidence JSON: `p14-linux-x64.json` (P13/P2 results recorded in `matrix.md` / `matrix.json`).

## Notes

- Spike evidence remains under `spikes/`; disposable hosts are not referenced by `Sav.Host`.
- Production analyzer **not** implemented (M004a still separate).
- `libpg_query` `Normalize` replaces literals only; spike uses Deparse (pgsqlparser) and/or native fingerprint for whitespace/case equivalence.
- Linux ICU gap is an environment limitation of this WSL image, not a missing `libpg_query`/`pg_query` native asset.

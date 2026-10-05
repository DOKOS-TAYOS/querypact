# Parser comparison spike evidence

This directory contains the retained evidence for the PostgreSQL parser spike
recorded in [ADR 0002](../../docs/adr/0002-postgres-parser-spike.md).

## Retained artifacts

- `corpus/adversarial.sql`: synthetic P01-P11 inputs.
- `results/matrix.md` and `results/matrix.json`: comparison and packaging results for `pgsqlparser` 1.0.0 and `PostgresQuery` 0.1.4.
- `results/p14-linux-x64.json`: Linux/WSL parser evidence. Linux is CI/spike evidence only, not an MVP product RID.
- `results/license-notes.md`: redistribution and maintenance review.
- `../../build/NativeLibPgQuery.props`: shared profile-1 native extraction setting used by production packaging.

## Evidence status

The spike hosts named in the matrix (`Spike.PgsqlParserHost` and
`Spike.PostgresQueryHost`) were disposable evaluation projects. Their source is
not retained in this checkout; the files in this directory are archival
evidence, not a locally rerunnable test project. The matrix records the exact
package versions, runtime, RIDs, publish profile, and P14 globalization note
needed to reconstruct the evaluation if a future parser decision reopens it.

The production parser is the Chosen `pgsqlparser` 1.0.0 adapter under
`src/Sav.Infrastructure.Postgres/Parsing/`. No production project depends on
the disposable spike hosts.

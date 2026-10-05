# ADR 0004: Third `libpg_query` wrapper contingency

- **Status:** Accepted as contingency method only: **not activated**. Activation needs a recorded dual-fail or stub-only stop in ADR 0002 / `CHANGELOG.md`. Until then, do not start third-wrapper implementation.
- **Date:** 2026-07-24

## Context

SQL-capable depends on ADR 0002 recording a Chosen package + packaging profile. If both `pgsqlparser` and `PostgresQuery` fail packaging profiles 1 and 2, or the spike time-box expires without a go, the product defaults to stub-only. Drafting this ADR only after failure would delay recovery, so the third-wrapper path is pre-declared here.

## Decision (inactive until activation)

### Activation triggers

Exactly one required, recorded in ADR 0002 / CHANGELOG:

1. Dual-fail: both spike wrappers fail packaging profiles 1 and 2, or
2. Time-box stub-only stop: spike exceeds ~15 business days without Chosen + packaging profile go, stub-only is recorded as default, and we elect to pursue a third wrapper.

### Activation actions

1. ADR 0002 / CHANGELOG records activation with trigger id and date.
2. Freeze production analyzer / SQL-capable feature work that depended on the failed Chosen path.
3. Start a new spike under this ADR (do not reuse failed Chosen claims).
4. Evaluate exactly one third wrapper from the shortlist below (or document shortlist exhaustion and stay stub-only permanently).

### Candidate shortlist (order)

| Order | Candidate | Constraint |
| --- | --- | --- |
| 1 | Another maintained .NET binding of `libpg_query` (not the two we already tried) with win-x64 natives, OSI-compatible redistribution, `net10.0` restore | No second language runtime |
| 2 | Thin P/Invoke wrapper in this repo around official `libpg_query` native artifacts | C/C++ native only; shared `build/NativeLibPgQuery.props` |
| 3 | None: permanent stub-only | Record permanent stub-only; no SQL-capable marketing |

Evaluate in order; stop at the first that passes ADR 0002 matrix P01-P15 on profile 1 (or profile 2 if profile 1 fails for that wrapper).

### While inactive

- Do not change Chosen package in ADR 0002
- Do not authorize SQL-capable work from this ADR alone
- Do not invent a second product story

## Consequences

### Positive

- Plan B exists before sinking more Domain/policy investment into a failed packaging path
- Activation criteria are tied to ADR / CHANGELOG evidence

### Trade-offs

- A third wrapper may still fail packaging; stub-only remains the default outcome
- Extra ADR maintenance until ADR 0002 resolves
- Domain/YAML work that ran spike-parallel is disposable on dual-fail: do not weaken packaging go to save sunk cost

### Rejected alternatives

| Alternative | Why not |
| --- | --- |
| Wait until after dual-fail to draft this ADR | Delays recovery |
| Introduce Python `pglast` or another second runtime | Forbidden by ADR 0001 |
| Mark SQL-capable shippable without native packaging proof | Violates ADR 0002 |

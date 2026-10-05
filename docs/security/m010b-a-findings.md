# M010b-A findings (MVP-A security remediation)

**Date:** 2026-07-25
**Branch:** `feat/010b-a-security-remediation`
**Budget:** ≤10 approved Critical/High remediations this milestone.

## Summary (machine-readable)

```json
{
  "schemaVersion": 1,
  "band": "MVP-A",
  "milestone": "M010b-A",
  "openCritical": 0,
  "openHigh": 0,
  "remediatedThisMilestone": 0,
  "overflowMilestone": null,
  "skipM010cA": true
}
```

| Metric | Value |
| --- | --- |
| Open Critical | **0** |
| Open High | **0** |
| Remediated this milestone | 0 (none approved/blocking) |
| Overflow `M010c-A` | **skip** (0 Critical and 0 High remain) |

## Approved Critical / High list (budget ≤10)

None.

Evidence:

- Earlier security review and remediation records: **0 CRITICAL / 0 HIGH** (approved remediations were Medium/Low only).
- MVP-A security corpus `tests/fixtures/security/benchmark-corpus-mvp-a.json` waves 1-3: all case IDs present and green (`SecurityBenchmarkMvpAWave1/2/3Tests`).
- No new Critical/High findings opened against the MVP-A track during M010a-A-harness / corpus w1-w3.

## Medium waivers (explicit)

| Id | Severity | Status | Waiver code | Notes |
| --- | --- | --- | --- | --- |
| `symlink_windows_detection_limit` | Medium | **Waived** | SYM-WIN | Carried from `docs/security/findings.md`. On Windows without Developer Mode / `SeCreateSymbolicLinkPrivilege`, CI cannot reliably create symlink escape fixtures. Product mitigation: `ConfigPathResolver` rejects reparse points and final paths outside `Sav:ConfigRoot` via `GetFinalPathNameByHandle` when the path exists. Non-symlink `..` / absolute escapes remain hard-fail tested. Does **not** block M011a. |

## Regressions

No Critical/High remediations → no per-finding files under `tests/Sav.Security.Tests/Regressions/`.
Bar lock: `tests/Sav.Security.Tests/Regressions/M010bAFindingsBarTests.cs` asserts `openCritical == 0` and `openHigh == 0` from the JSON block above.

## Release gate

M011a may proceed on the MVP-A security track with respect to Critical/High (corpus green + this file). Medium residual: SYM-WIN waiver only.

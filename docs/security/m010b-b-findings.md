# M010b-B findings (MVP-B security remediation)

**Date:** 2026-07-25
**Branch:** `feat/010b-b-security-remediation`
**Budget:** ≤10 approved Critical/High remediations this milestone.

## Summary (machine-readable)

```json
{
  "schemaVersion": 1,
  "band": "MVP-B",
  "milestone": "M010b-B",
  "openCritical": [],
  "openHigh": [],
  "remediatedThisMilestone": [
    "mvp-b-verify-query-silent-drop-query-equivalent",
    "mvp-b-benchmark-schema-orphan-hollow-runner",
    "mvp-b-equivalence-missing-plan-gate",
    "mvp-b-migration-alias-corpus-skips-di-allow-path",
    "mvp-b-cli-savexception-unredacted"
  ],
  "overflowMilestone": null,
  "skipM010cB": true
}
```

| Metric | Value |
| --- | --- |
| Open Critical | **0** (`[]`) |
| Open High | **0** (`[]`) |
| Remediated this milestone | **5** (1 High + 4 Medium) |
| Overflow `M010c-B` | **skip** (0 Critical and 0 High remain) |

## Approved High (obligatory)

| Id | Severity | Status | Fix |
| --- | --- | --- | --- |
| `mvp-b-verify-query-silent-drop-query-equivalent` | High | **Remediated** | `SelectVerifyQueryProperties` treats `QueryEquivalentSpec` and unknown `_` as `unsupported_construct` Error (never silent drop). Regression: `QueryEquivalentForbiddenOnVerifyQueryTests`. |

## Approved Medium (fit in budget)

| Id | Severity | Status | Fix |
| --- | --- | --- | --- |
| `mvp-b-benchmark-schema-orphan-hollow-runner` | Medium | **Remediated** | Corpus runner invokes owner Fact (not source grep). |
| `mvp-b-equivalence-missing-plan-gate` | Medium | **Remediated** | `VerifyEquivalenceUseCase` injects `IPlanProvider`; plan Deny/Review → oracle CallCount == 0. |
| `mvp-b-migration-alias-corpus-skips-di-allow-path` | Medium | **Remediated** | Corpus also runs DI allow-path Fact (`ResolveCount==0` + ephemeral fingerprint). |
| `mvp-b-cli-savexception-unredacted` | Medium | **Remediated** | `CliJson.WriteSavException` redacts via `PostgresErrorRedactor`/`StrictRedactor` (parity with MCP). |

## Out of scope (not remediated)

| Id | Severity | Notes |
| --- | --- | --- |
| `mvp-b-ensure-equivalent-select-pair-safe-single-ir` (L1) | Low | **Remediated** | Equivalence now carries distinct left/right IRs and validates each SQL against its matching IR. |

## Regressions

- `tests/Sav.Application.Tests/Verify/QueryEquivalentForbiddenOnVerifyQueryTests.cs`
- `tests/Sav.Application.Tests/Verify/VerifyEquivalenceUseCaseTests.Plan_deny_or_review_skips_oracle`
- `tests/Sav.Host.Tests/CliSavExceptionRedactionTests.cs`
- Bar lock: `tests/Sav.Security.Tests/Regressions/M010bBFindingsBarTests.cs`

## Release gate

M010c-B **skipped**. Do **not** open M010c-B from this milestone; the MVP-B security bar is closed at M010b-B.

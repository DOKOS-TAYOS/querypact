# Security benchmark

## Pass criteria

Do not ship a SQL-capable release with open Critical or High findings from the MVP-A benchmark track. Same rule for claiming full MVP with the MVP-B track open.

| Severity | Release rule |
| --- | --- |
| Critical | Must be closed before the corresponding band release |
| High | Must be closed before the corresponding band release |
| Medium | May defer only with an explicit waiver row in the findings file |
| Low | Tracked; does not block release by itself |

## Corpus fixture (MVP-A)

- Path: `tests/fixtures/security/benchmark-corpus-mvp-a.json`
- Band: `MVP-A`
- Populated across corpus waves; harness starts with schema + empty cases

## Corpus fixture (MVP-B)

- Path: `tests/fixtures/security/benchmark-corpus-mvp-b.json`
- Band: `MVP-B`
- Tests: `tests/Sav.Security.Tests/Benchmark/SecurityBenchmarkMvpBTests.cs`
- Remediation of open Critical/High findings is tracked in `m010b-b-findings.md` (and follow-ups if needed)

### Case groups (MVP-B)

| Group | Case id(s) | Owner |
| --- | --- | --- |
| Identifier injection unique/non_null | `unique_non_null_identifier_injection` | `UniqueNonNullIdentifierBypassTests` |
| UniqueNonNull NoLeak | `unique_non_null_no_row_leak`, `unique_non_null_notice_leakage` | `UniqueNonNullNoRowLeakTests`, `UniqueNonNullNoticeLeakageTests` |
| verify_migration never real alias | `verify_migration_never_real_alias` | `VerifyMigrationNeverUsesRealAliasE2ETests` |
| policy-before-apply | `verify_migration_policy_before_apply` | `VerifyMigrationDeniesBeforeApplyTests` |
| Remaining oracle bypass | `oracle_template_bypass_query_equivalent`, `schema_orphan_identifier_bypass`, `affected_rows_exact_shape`, `affected_rows_never_real_alias` | `QueryEquivalentTemplateBypassTests`, `SchemaOrphanIdentifierBypassTests`, `AffectedRowsExactShapeTests`, `AffectedRowsNeverUsesRealAliasTests` |
| schema/orphan forbidden on verify_query | `schema_orphan_forbidden_on_verify_query` | `VerifyQuerySchemaPropsForbiddenOnRealAliasTests` |
| MVP-B egress redact | `egress_verify_equivalence_host_di`, `egress_verify_migration_host_di`, `egress_cli_verify_equivalence_and_migration`, `egress_mcp_verify_equivalence_and_migration` | `AllEgressPathsRedactObjectVerifyHostTests` |

## JSON schema (schemaVersion 1)

Root object:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schemaVersion` | number | yes | Must be `1` |
| `band` | string | yes | `MVP-A` or `MVP-B` |
| `cases` | array | yes | May be empty `[]` for harness skeleton |

Each case record:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | yes | Stable case id; unique within the corpus |
| `wave` | number | yes | `1`, `2`, or `3` (MVP-B corpus uses `1`) |
| `severity` | string | yes | Exact casing: `Critical` \| `High` \| `Medium` \| `Low` |
| `category` | string | yes | Threat area (e.g. `bypass`, `path`, `hmac`, `oracle`, `noleak`, `host`, `egress`, `authorize`, `surface`) |
| `title` | string | yes | Short description |
| `ownerTest` | string | yes | Fully-qualified owner test that proves the case |
| `expectedOutcome` | string | yes | Expected outcome (e.g. `deny`, `refuse`, `redact`, `absent`, `pass`) |

Example:

```json
{
  "schemaVersion": 1,
  "band": "MVP-A",
  "cases": [
    {
      "id": "multi_statement_bypass",
      "wave": 1,
      "severity": "Critical",
      "category": "bypass",
      "title": "Multi-statement agent SQL is denied",
      "ownerTest": "Sav.Security.Tests.Bypass.CteSubqueryAliasTests",
      "expectedOutcome": "deny"
    }
  ]
}
```

## Harness

- Tests: `tests/Sav.Security.Tests/Benchmark/SecurityBenchmarkHarnessTests.cs`
- Loader/runner: `tests/Sav.Security.Tests/Benchmark/SecurityBenchmarkCorpus.cs` (`LoadMvpA`, `LoadMvpB`)
- Empty `cases: []` must load, validate, and run green for the MVP-A harness
- Wave tests (MVP-A) and `SecurityBenchmarkMvpBTests` assert required case ids are present and green

## Related

- Waived residual example: `docs/security/findings.md` (`symlink_windows_detection_limit`)
- MVP-A remediation: `docs/security/m010b-a-findings.md`
- MVP-B remediation: `docs/security/m010b-b-findings.md`
- Adversarial SQL fixtures (parser/policy): `tests/fixtures/sql/adversarial-corpus.json` (separate from this benchmark index)

# Security model

This document describes the MVP's security assumptions and boundaries. It is not a certification that arbitrary agent-generated SQL or an arbitrary PostgreSQL deployment is safe. The shipped implementation, accepted ADRs, and security tests take precedence if this document becomes outdated.

Linux x64 is currently supported for running QueryPact from source. Windows
x64 source restore/build/test compatibility is validated, while Windows
executable runtime and distribution are not a supported public release surface.
No prebuilt binaries are distributed; macOS is unverified. `Sav.*` namespaces,
`SAV_*` configuration keys, and `sav_ro_probe` are compatibility/internal
contracts and do not make platform-support claims.

## Assumptions and assets

An agent may make mistakes, be compromised, follow prompt-injection instructions, attempt to access forbidden data, or propose expensive or destructive SQL. The operator controls target aliases, database privileges, policies, contracts, and credentials; the agent must not provide connection strings.

The protected assets include database rows, credentials, sensitive schema information, plans, statistics, logs, policy integrity, availability, and attestation integrity.

## Threats

- Destructive DML or DDL and policy bypass through CTEs, aliases, subqueries, or multiple statements.
- Functions, operators, triggers, or other PostgreSQL features with side effects.
- Data disclosure through returned rows, aggregates, errors, execution timing, or plans.
- Denial of service and excessive database resource consumption.
- Confused-deputy behavior, parser discrepancies, and time-of-check/time-of-use (TOCTOU) changes.
- Forged or modified attestations.

## Controls

- PostgreSQL permissions and dedicated, minimally privileged target roles.
- Operator-controlled target aliases; agents cannot supply DSNs.
- Native PostgreSQL parsing and fail-closed YAML authorization.
- A plan gate whose outcomes are `Allow`, `Deny`, or `Review`; policy `Deny`/`Review` short-circuits before a database session, plan, or property oracle where applicable.
- Statement/lock timeouts, cancellation, and a wall-clock verification guard.
- Checked read-only transactions for real aliases and ephemeral PostgreSQL for migrations.
- Structured property templates, strict redaction, and operator-keyed HMAC attestations.
- A `Review` outcome represented as an attestation decision, not an automated human approval workflow. `IApprovalProvider`-based approval is post-MVP.

## MVP guarantees and their boundaries

- Real row payloads are not returned in responses, strict logs, or attestation bodies. This does **not** mean zero server-side reads, CPU/I/O, timing leakage, `NOTICE` messages, or function-related effects while evaluating `verify_*` properties. A snapshot-only oracle would require additional development.
- QueryPact does not intentionally execute application-table writes against real targets. PostgreSQL permissions, the read-only transaction, and the canary guard remain necessary; unsafe triggers, rules, or foreign-key effects associated with the canary can occur before rollback.
- Unparsable and unsupported SQL is rejected. PostgreSQL `MERGE` is unsupported, including when nested in `EXPLAIN` or `EXPLAIN (ANALYZE)`, and is rejected with `unsupported_construct` even if the policy lists its statement type as allowed. Its action-column metadata is not complete.
- Strict egress must not contain DSNs, passwords, stack traces, raw PostgreSQL `DETAIL`/`HINT`/`CONTEXT`, raw rows, or disallowed plan literals and exact cardinalities.
- Migrations run against ephemeral PostgreSQL, not a real target alias.
- The local attestation HMAC covers the redacted body and requires `SAV_ATTESTATION_HMAC_KEY` with a `base64:` or `hex:` prefix and at least 32 decoded bytes. It provides local tamper detection, **not** publisher authenticity, asymmetric signing, or cross-host trust without securely sharing the key.
- Equivalence checks evaluate both `EXCEPT ALL` directions within one PostgreSQL statement snapshot. Schema fingerprints mitigate some TOCTOU risks at checkpoints; they do not provide complete isolation.

## Required `sav_ro_probe` setup

Before `verify_query` opens a real read-only alias, the following setup is required:

1. Create `public.sav_ro_probe` with a `probe_key text` column and no triggers, rules, or foreign-key actions that write outside the canary table.
2. Give the dedicated read-only role only the necessary `INSERT` permission on the canary, configure `default_transaction_read_only=on`, and withhold unnecessary write privileges on application objects.

Recommended operator preflight (not a runtime prerequisite): run
`dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- check-target --target <alias>`
and investigate its warnings. For sensitive deployments use `--strict`, which
also rejects advisory findings.

The runtime guard requires `SHOW transaction_read_only=on` in the newly opened transaction before attempting its controlled canary `INSERT`. A missing canary rejects the session as `ro_probe_missing`. `AnalyzeOnly` and `analyze_sql` do not require the canary.

`check-target` inspects catalog-visible privileges and canary setup, including inherited privileges and roles reachable through `SET ROLE`. Standard mode warns about ordinary excess privileges; `--strict` also rejects them. The check needs neither the Full-mode HMAC key nor a canary write and is **not** rerun automatically on every query. It cannot establish that all permitted functions are side-effect-free, certify other databases, or guarantee privileges will remain unchanged.

### Canary outcomes

| Outcome | Result | Session |
| --- | --- | --- |
| `SHOW transaction_read_only=on` and canary fails with the read-only SQLSTATE | Canary passes | Accepted |
| Probe table missing | `ro_probe_missing` | Rejected |
| Canary `INSERT` succeeds and rollback is confirmed | `role_not_read_only` | Rejected |
| Canary succeeds but rollback cannot be confirmed | `ro_canary_rollback_unconfirmed` | Rejected; alias marked unsafe |
| Any other canary result, including a permission/check error | `ro_canary_inconclusive` | Rejected |

There is no implicit accept path. See the `ReadOnlyRoleEnforcementTests` regression coverage and the [operator probe runbook](../release/ro-probe-setup.md).

## Non-guarantees

QueryPact does **not** provide:

- Formal anonymity, differential privacy, or immunity to reverse engineering.
- Proof of correct behavior when a policy or contract omits an important requirement.
- Elimination of timing or other side channels, or zero database resource consumption.
- A proof that arbitrary allowed functions and operators lack side effects.
- A guarantee that canary-related triggers or foreign-key actions cause zero transient effects before rollback.
- Strong TOCTOU isolation; the MVP checks selected schema fingerprints and may return `REVIEW` when drift is detected.
- Globally trusted attestations or digital publisher signatures.
- Oracle support for delimited/mixed-case identifiers that fail the MVP identifier gate; such input is rejected rather than guessed.

See the [CLI and MCP reference](../CLI_REFERENCE.md), [developer guide](../DEVELOPER_GUIDE.md), and [vulnerability reporting policy](../../SECURITY.md).

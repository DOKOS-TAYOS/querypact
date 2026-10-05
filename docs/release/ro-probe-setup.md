# Operator runbook: `sav_ro_probe` for `verify_query`

For operators running QueryPact in Full mode against a real PostgreSQL alias.
Linux x64 is the supported platform for running from source; see the
[README](../../README.md#build-from-source). Windows executable examples in
this runbook are interface examples, not a supported public runtime or binary
distribution promise. No prebuilt binaries are distributed. Without this
probe, `verify_query` refuses to open a read-only session (`ro_probe_missing`).
AnalyzeOnly / `analyze_sql` do not need this.

## Why

QueryPact verifies that the alias transaction starts read-only, then attempts a controlled DML canary `INSERT` into `public.sav_ro_probe` and confirms abort/rollback. This proves the transaction behavior, **not** that the role lacks write privileges. The table must exist; triggers must not write outside it.

## DDL (once per target database)

```sql
CREATE TABLE IF NOT EXISTS public.sav_ro_probe (
    probe_key text PRIMARY KEY
);

COMMENT ON TABLE public.sav_ro_probe IS
  'QueryPact read-only session DML canary target; do not attach triggers that write other tables';
```

## Role grants

Replace `sav_ro` with the operator’s read-only role name:

```sql
GRANT USAGE ON SCHEMA public TO sav_ro;
GRANT INSERT ON TABLE public.sav_ro_probe TO sav_ro;
-- Do not grant INSERT/UPDATE/DELETE on application tables to sav_ro.
-- Require default_transaction_read_only=on for the alias role; QueryPact verifies this before accepting the canary.
```

## Operator privilege preflight

Run this diagnostic after binding the target alias and before the first verification, and repeat it when changing the role, grants, or database schema:

```sh
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- check-target --target prod_ro
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- check-target --target prod_ro --strict
```

This command also works with `--mode AnalyzeOnly` and does **not** require an attestation HMAC key. It uses only the configured alias and read-only PostgreSQL catalog queries. It does not issue the canary INSERT and does not change the runtime session guard.

The JSON response includes `passed`, `strict`, `errors`, and `warnings`, with stable finding codes and no connection strings, object names or role names. An error causes a nonzero exit code in both modes. Standard mode reports ordinary excess privileges as warnings without blocking; `--strict` also returns a nonzero exit code for warnings.

Mandatory errors:

- `transaction_not_read_only`: the alias does not start read-only.
- `privileged_role`: administrative role attributes or effective/reachable privileged roles were found.
- `probe_missing_or_insert_denied`: the canary table or required INSERT grant is missing.

Advisory findings, rejected in strict mode:

- `table_write_access`: effective write/column privileges or ownership over non-canary user relations.
- `sequence_write_access`: effective sequence modification privileges or ownership.
- `create_access`: database/schema CREATE privilege.
- `security_definer_executable`: an executable user-defined SECURITY DEFINER function.

The inspector considers inherited privileges and roles reachable through `SET ROLE`. It deliberately exempts only the canary table's INSERT privilege. `--strict` checks the catalog-visible privileges **in the currently connected database**; it does not prove that functions are free of side effects, certify other databases, or prevent privileges from changing later. It is an operator preflight, not a substitute for a dedicated minimally privileged role, SQL allow-lists, or the mandatory read-only runtime transaction. It can flag legitimate extension functions for operator review.

## Do not

1. Install triggers, rules, or FK actions on `sav_ro_probe` that write any other table.
2. Use a superuser or table-owner role with write privileges on application data as the alias DSN role.
3. Skip this setup and expect `verify_query` to start. QueryPact fails closed with `ro_probe_missing`.
4. Treat permission errors, check violations, aborts, or other non-read-only SQLSTATEs on the canary as “good enough”. QueryPact refuses with `ro_canary_inconclusive`. Fix grants / probe DDL, then retry.

## Canary outcomes

| What you see / cause | QueryPact response |
| --- | --- |
| Probe table missing | `ro_probe_missing` |
| Transaction starts read-only (INSERT rejected as read-only) | Session accepted |
| INSERT into probe succeeds (transaction was writable) | `role_not_read_only` |
| Canary fails for any other reason | `ro_canary_inconclusive` |
| INSERT appears to succeed but rollback cannot be confirmed | `ro_canary_rollback_unconfirmed` (alias marked unsafe) |

## Checklist before first `querypact verify-query`

- [ ] `public.sav_ro_probe(probe_key text)` exists
- [ ] Alias DSN role has `default_transaction_read_only=on` and can `INSERT` into `sav_ro_probe` only as needed for the canary
- [ ] No write triggers on `sav_ro_probe` targeting other tables
- [ ] Alias binding points at this database; DSN comes from env / protected local config (never agent-supplied)
- [ ] Run `dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- check-target --target <alias>` and investigate warnings; use `--strict` for sensitive deployments
- [ ] Smoke: Full-mode `dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- verify-query` against a synthetic allow-listed contract reaches session open (or fails for policy/SQL reasons other than `ro_probe_missing`)

## Related

- [`docs/product/02_SECURITY_MODEL.md`](../product/02_SECURITY_MODEL.md)
- [Windows QueryPact verification step](windows-querypact-verification.md)

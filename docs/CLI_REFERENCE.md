# CLI and MCP reference

This is the operational reference for the QueryPact host. Use the
[read-only probe runbook](release/ro-probe-setup.md) before connecting it to a
real PostgreSQL database.

Linux x64 is the supported platform for running QueryPact from source. Build
with the commands in the [README](../README.md#build-from-source), then invoke
the CLI with `dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release --`
followed by the command and its arguments. Executable-form examples below
describe the CLI interface; no prebuilt binaries are distributed. Windows
source compatibility is validated, but executable runtime/distribution is not
a supported public release surface. macOS is unverified.

## Output and transport

CLI success is JSON on stdout. Domain failures are structured JSON on stderr and
normally return exit code `1`. Host startup failures, such as invalid mode or
missing Full-mode HMAC, return `2`. Help/version do not require Full services.

`querypact mcp serve` uses MCP over stdio. Protocol output is exclusively stdout;
logs/errors are stderr. Do not insert a banner, debugging output, or a
stdout-writing proxy between an MCP client and QueryPact.

## Configuration

| Setting | Required for | Meaning |
| --- | --- | --- |
| `SAV_MODE` | Optional | `AnalyzeOnly` or `Full`; default Full |
| `--mode` | Optional | Per-invocation override |
| `SAV_CONFIG_ROOT` | Recommended | Absolute root for policy, contract, schema, and migration paths; current directory if unset |
| `SAV_ATTESTATION_HMAC_KEY` | Full | `base64:` or `hex:` value that decodes to at least 32 bytes |
| `SAV_ATTESTATION_STORE_ROOT` | Full, optional | Attestation directory; default LocalApplicationData `sav/attestations` (kept for compatibility with existing installations) |
| `SAV_TARGETS_JSON` | Alias verification | Alias-to-DSN-environment-variable-name JSON map |
| `targets.json` | Alternative map | Same map under config root; environment overlays matching file aliases |

All paths must resolve under `SAV_CONFIG_ROOT`. Traversal is refused. The optional
`targets.json` uses the same symlink/reparse-point and final-path checks as
policy and contract files; a linked targets file is rejected rather than loaded.
Never put
real DSNs in input files, arguments, `targets.json`, or `SAV_TARGETS_JSON`.

```powershell
$env:SAV_MODE = 'Full'
$env:SAV_CONFIG_ROOT = 'C:\querypact-config'
$env:SAV_ATTESTATION_HMAC_KEY = 'base64:<at-least-32-decoded-bytes>'
$env:SAV_TARGETS_JSON = '{"reporting_ro":"SAV_REPORTING_RO_DSN"}'
$env:SAV_REPORTING_RO_DSN = 'Host=db.example;Database=reporting;Username=sav_ro;Password=...'
```

The map contains only a DSN variable **name**. The equivalent
`C:\querypact-config\targets.json` is:

```json
{ "reporting_ro": "SAV_REPORTING_RO_DSN" }
```

Protect the process environment: aliases do not replace secrets management or
PostgreSQL privileges.

## YAML inputs

A policy needs `id`, `version`, controls for SQL and plan behavior, and a
disclosure profile.

```yaml
id: readonly-select
version: "1"
allowedStatementTypes: [Select]
deniedTables: []
deniedColumns: []
allowedFunctions: []
denyUnresolvedObjects: true
denyMultipleStatements: true
denyUpdateDeleteWithoutPredicate: true
maxCostBucket: high
forbiddenPlanNodes: []
disclosure:
  name: strict
  includePlanSummary: false
  includeObjectNames: false
  includeTimings: false
  includeRowCounts: false
```

`allowedFunctions` uses unqualified names for PostgreSQL builtins: an explicit
`pg_catalog.<function>` call is canonicalized to `<function>`. Functions
qualified with any other schema remain qualified and require that exact
`schema.function` entry in the allow-list. During real-alias verification,
an unqualified function name is rejected when an executable visible
non-`pg_catalog` definition with that name exists; qualify intentional custom
functions explicitly in both SQL and policy.

Function entries match parser-normalized names exactly, with case-sensitive
comparison. PostgreSQL folds unquoted SQL identifiers to lowercase and preserves
double-quoted identifier case. For example, `sav_scope.sav_safe_fn` authorizes
`SAV_SCOPE.SAV_SAFE_FN()` and `"sav_scope"."sav_safe_fn"()`, but not
`sav_scope."SAV_SAFE_FN"()` or `"SAV_SCOPE".sav_safe_fn()`. To authorize the quoted
uppercase function explicitly, use the policy entry `sav_scope.SAV_SAFE_FN`
(without SQL identifier quotes). Delimited function components containing dots
remain unsupported and fail closed.

CTE names are resolved within their lexical WITH scopes. For non-recursive WITH, a CTE is visible to later definitions and the statement body, but not to its own definition; schema-qualified relation names and DML targets always denote physical relations. This ensures that catalog checks and denied-table policy cannot be skipped for a physical relation sharing a CTE name.

Whole-row references, such as `SELECT u FROM users AS u`, are rejected as `unsupported_construct` because they can include columns excluded by `deniedColumns` without naming them. The raw parser cannot always distinguish a bare column from an identically named range binding, so ambiguous bare references also fail closed; explicit column references such as `u.email` remain supported. This applies during static analysis as well as real-alias verification. JOIN USING keys are tracked as column reads, including when they are omitted from the projection. JOIN USING column aliases are checked for potential whole-row references; NATURAL JOIN is rejected because its implicit column reads cannot be determined from the raw parse tree. CTE definitions and non-LATERAL derived tables do not inherit outer range bindings.

PostgreSQL `MERGE` statements are unsupported by the current MVP and always fail closed as `unsupported_construct`, even if `MergeStmt` appears in `allowedStatementTypes`. The same rejection applies to `EXPLAIN MERGE` and `EXPLAIN (ANALYZE) MERGE`, even when the policy permits `ExplainStmt`; the latter wrapper can execute its underlying statement. The parser preserves available statement and relation facts, but does not collect every MERGE action destination column; do not rely on `deniedColumns` to identify all MERGE writes.

Before real-alias planning or execution, casts and coercions must also pass a
catalog-only conversion gate. Ordinary PostgreSQL built-in casts, arrays, and
type modifiers remain supported. Custom types (including domains and enums),
unresolved cast targets, and inconclusive catalog results fail closed with
`unsupported_construct`. The gate conservatively checks all column types of
referenced relations and all matching function/operator signatures, even when
an individual column or overload might not be selected. Column names in the IR
are flattened: they do not retain relation binding through aliases, CTEs, or
nested scopes. Selecting only a built-in column (or a constant) from a relation
with any custom column therefore still rejects verification.

Added conversion paths between built-in types reject verification unless the
parser proves a single, clause-free `SELECT` whose output consists exclusively
of literals represented by its signed 32-bit integer nodes, with optional output
aliases. For example,
`SELECT 1` and `SELECT 0 AS first, 7 AS last` do not need a conversion path and
remain supported in a database with an unrelated custom cast. The built-in
`int4` type and its input/output metadata must still pass the catalog check.
An equivalence pair receives this exception only when both queries have this
proven shape and the same output column count: the `EXCEPT` wrapper then needs
no type coercion. Strings, nulls, booleans, larger/decimal numeric literals,
explicit casts, expressions, clauses, subqueries, and set operations retain the
conservative check. The raw parse tree does not establish which implicit or
assignment path these other forms will choose. Both sides of equivalence share
the check and are rejected together on uncertainty.
This also covers automatic input/output conversions absent from `pg_cast`.

A contract needs `id`, `version`, a disclosure profile, and at least one object
under `requiredProperties`. Bare property strings are rejected.

```yaml
id: no-pending-orders
version: "1"
requiredProperties:
  - name: query_succeeds
  - name: empty_result
disclosure:
  name: strict
  includePlanSummary: false
  includeObjectNames: false
  includeTimings: false
  includeRowCounts: false
```

`unique` and `non_null` need `column`. `affected_rows` requires
`minInclusive` and may set `maxInclusive`. `schema_invariant` requires relation
requirements with `relkind` in the closed vocabulary `r`, `S`, `v`, `m`, `c`,
`t`, `f`, or `p`; index kinds `i` / `I` are not supported because schema
snapshots do not produce relation digests for indexes. `no_new_orphans` needs
parent/child table and key names. It is a strict postcondition: it passes only
when zero orphan rows exist after the migration, so an orphan already present
in the base schema also makes the property fail. It does not mean merely that
the orphan count must not increase. Effective disclosure intersects policy and
contract disclosure; inputs cannot relax it.

## Commands

Root syntax:

```text
querypact [--mode AnalyzeOnly|Full] <command> [options]
```

### Analyze

Available in both modes:

```text
querypact analyze --sql <sql> --policy <path> [--contract <path>]
```

```sh
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- --mode AnalyzeOnly analyze --sql 'SELECT id FROM orders' --policy policies/readonly.yaml --contract contracts/no-pending-orders.yaml
```

It parses SQL and evaluates policy. It does not open PostgreSQL, execute SQL, or
create an attestation. An `allow` is a policy decision, not a general execution
permit.

### Verify query

Full mode only:

```text
querypact verify-query --sql <sql> --target <alias> --policy <path> --contract <path>
```

```sh
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- verify-query --sql "SELECT id FROM orders WHERE status = 'pending'" --target reporting_ro --policy policies/readonly.yaml --contract contracts/no-pending-orders.yaml
```

It performs catalog, estimated-plan, and allowed property checks on a real
**read-only alias**, then stores a redacted HMAC attestation. Set up
`public.sav_ro_probe` and the dedicated read-only role first. Real aliases
support `query_succeeds`, `empty_result`, `unique`, and `non_null`.
Real-alias verification currently rejects PostgreSQL views, materialized
views, partitioned tables, and inheritance parents because deny-list policy
cannot yet be checked safely against relations read indirectly through those
objects.
`schema_invariant`, `no_new_orphans`, and `affected_rows` return
`property_environment_forbidden`; `query_equivalent` belongs to equivalence.

### Verify equivalence

Full mode only:

```text
querypact verify-equivalence --left-sql <sql> --right-sql <sql> --target <alias> --policy <path> --contract <path>
```

```sh
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- verify-equivalence --left-sql 'SELECT id FROM customers WHERE active' --right-sql 'SELECT id FROM customers WHERE active = TRUE' --target reporting_ro --policy policies/readonly.yaml --contract contracts/equivalent.yaml
```

Use a contract with `query_equivalent`. Its result is a bounded property check,
not a mathematical proof for arbitrary PostgreSQL behavior.

### Verify migration

Full mode only:

```text
querypact verify-migration (--migration-sql <sql> | --migration-path <path>) --base-schema <path> --policy <path> --contract <path>
```

```sh
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- verify-migration --migration-path migrations/add-index.sql --base-schema schemas/base.sql --policy policies/migrations.yaml --contract contracts/migration-invariants.yaml
```

Exactly one migration input is required. There is no `--target` because this
always uses ephemeral PostgreSQL. Docker must be available. Policy deny/review
or parse failure occurs before migration application. Ephemeral
`affected_rows` evaluates the row count returned by that migration execution;
the migration is not executed a second time for the property check.

### Get attestation

Full mode only:

```text
querypact attestation get --id <uuid>
```

```sh
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- attestation get --id '01234567-89ab-cdef-0123-456789abcdef'
```

The stored value is integrity-checked before return. `attestation_not_found`
means no stored value; malformed JSON, missing/null required fields, and HMAC
mismatches or omissions from the canonical stored structure return the typed
`attestation_integrity_failure` error without exposing the stored payload.
JSON property ordering does not affect integrity. A tampered record is never
silently accepted.

### Serve MCP

Available in both modes (configure the MCP client to launch `dotnet` with
the source project and arguments shown below):

```text
querypact mcp serve
```

```json
{
  "command": "dotnet",
  "args": ["run", "--project", "src/Sav.Host/Sav.Host.csproj", "-c", "Release", "--", "--mode", "AnalyzeOnly", "mcp", "serve"],
  "env": { "SAV_CONFIG_ROOT": "/path/to/querypact-config" }
}
```

AnalyzeOnly exposes only `analyze_sql`. Full additionally exposes
`verify_query`, `verify_equivalence`, `verify_migration`, and
`get_attestation`. Tool inputs mirror CLI options. MCP deliberately has no
arbitrary SQL executor.

## Decisions and common errors

| Outcome/code | Meaning and safe response |
| --- | --- |
| `allow` | Policy allowed the analyzed structure; not an external execution permit |
| `deny` | Policy, parser, or verification stage rejected the request; revise deliberately |
| `review` | Operator decision is needed; MVP has no automated human workflow |
| `PASS` / `FAIL` | Required properties passed / at least one failed |
| `schema_changed` | Fingerprint drift or 30-second guard; inspect database activity before retry |
| `ro_probe_missing` | Install the probe table and grants from the runbook |
| `role_not_read_only` | Alias role can write; fix PostgreSQL privileges, never bypass it |
| `ro_canary_inconclusive` / `ro_canary_rollback_unconfirmed` | Read-only proof unsafe; inspect probe triggers, grants, and DB state |
| `unsupported_construct` | SQL/property outside safe MVP subset; do not force it through |

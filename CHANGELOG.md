# Changelog

Notable changes to this project.

Entries dated before the public QueryPact repository describe private or predecessor development history. They do not represent QueryPact public releases, dates, or tags.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/) via MinVer when releases are tagged.

## [Unreleased]

### Added

- Include original native parser redistribution notices with immutable sources
  and hashes; select .NET runtime notices from the effective publish packs.
- Add offline release evidence, checksum and license reconciliation validation;
  report unresolved SPDX/physical coverage with an explicitly blocked public
  release gate and reject stale or incomplete publish output.

- Add a standalone `check-target` operator privilege preflight, with advisory standard mode and opt-in strict rejection, without requiring a Full-mode HMAC key or changing the runtime read-only guard.

### Fixed

- Reject PostgreSQL `MERGE`, including `EXPLAIN MERGE` and `EXPLAIN (ANALYZE) MERGE`, as `unsupported_construct` even when their statement types are permitted by policy; action-column metadata remains incomplete.

- Reject `affected_rows` contracts with `maxInclusive` below `minInclusive` during YAML loading, before any shadow migration is executed (BUG-006).

- Canonicalize the case-insensitive target alias when computing its fingerprint, so casing differences in requests do not split attestations for the same configured alias (BUG-005).

- Limit shadow migration verification to one active PostgreSQL container per process and cap each container at 1 GiB of memory and two CPUs; waiting requests honor cancellation (BUG-004).

- Preserve the UNC root when normalizing Windows extended final paths, so valid ConfigRoot network shares do not fail path containment checks (BUG-003).

- Capture shadow schema snapshots only for contracts requiring `schema_invariant`, so unrelated unsupported metadata does not block row-count or orphan checks.
- Preserve the successful shadow migration application state when a subsequent snapshot or property evaluation fails; report the failure on required properties instead of `shadow_apply`.

- Return typed attestation integrity failures for corrupt persisted JSON, including missing/null nested fields, value-typed defaults, and omissions from its canonical structure (BUG-008).

- Validate optional `targets.json` through the shared ConfigRoot path resolver, rejecting symlink/reparse-point redirection before loading alias mappings (BUG-006).

- Reject potential whole-row relation references that could include denied columns without naming them; account for JOIN USING keys and aliases, fail closed on NATURAL JOIN, and preserve explicit column references (BUG-004).

- Resolve CTE references using lexical WITH scopes so a CTE name cannot hide a physical relation in its definition or evade real-alias catalog checks (BUG-003).

- Validate PostgreSQL casts and coercion type dependencies before planning or executing real-alias queries, rejecting unproven conversion paths in single and pair verification (BUG-002).

- Avoid rejecting parser-proven simple integer-literal SELECTs because of unrelated custom casts, including matching projection shapes in equivalence pairs; retain catalog type checks and conservative rejection for unproven coercions and unused custom relation columns (BUG-002 compatibility).

- Validate unqualified function names against PostgreSQL catalog visibility before real-alias execution.

- Evaluate both directions of `query_equivalent` inside one PostgreSQL statement so concurrent writes cannot make the two `EXCEPT ALL` checks observe different statement snapshots.

- Fail closed on blank, comment-only, or otherwise statement-free SQL during parsing and policy evaluation.

- Correct the README environment description: equivalence runs on a real read-only PostgreSQL alias; only migration verification uses ephemeral PostgreSQL.

- Run the full GitHub Actions CI on pushes to `main` as well as pull requests, covering merged and directly pushed commits.

- Include view and materialized-view definitions in shadow schema digests so `schema_invariant` detects semantic changes without column changes.

- Use platform-correct case-sensitive path containment on Unix and reject symlinks in every ConfigRoot path component, not just the final file.

- Serialize attestation existence probes with reads and atomic overwrites, preventing concurrent saves and gets from failing with access denied on Windows.
- Keep columns referenced only by DML expressions, predicates, and subqueries in `ColumnsRead` instead of misclassifying them as write targets.
- Normalize surrounding whitespace in denied-table, denied-column, and forbidden-plan-node policy entries so negative rules cannot be disabled by quoted spacing.
- Require each `schema_invariant` relation to exist before the migration as well as after it, preventing same-relkind object replacement from passing.
- Reject duplicate YAML keys in policies and contracts instead of accepting ambiguous configuration.
- Start the `verify_equivalence` TOCTOU wall-clock budget before configuration, parsing, policy, session, and catalog work.
- Include column collation/identity/generated metadata and view definitions in the real-alias schema fingerprint so semantic schema drift triggers `schema_changed`.
- Make `schema_invariant` bind each required relation name to its declared PostgreSQL `relkind`, instead of relying only on global relation counts.
- Make the oracle's textual dangerous-verb fallback ignore comments, literals, dollar-quoted strings, and quoted identifiers while normalizing all whitespace, avoiding false positives without losing tab-separated write detection.
- Make `no_new_orphans` ignore rows whose child key is `NULL`, matching PostgreSQL foreign-key semantics for nullable references.
- Canonicalize schema-qualified function names without splitting their components, while only unqualifying the trusted `pg_catalog` schema.
- Align `schema_invariant` relkind validation with the relation kinds that schema snapshots can fully digest.
- Validate each side of `verify_equivalence` against its own SQL IR at the oracle boundary.
- Reject unknown contract YAML fields instead of silently ignoring typos that can weaken property constraints.
- Make `schema_invariant` fail closed when schema snapshots encounter unsupported delimited or mixed-case metadata identifiers.
- Reject data-modifying CTEs during analysis instead of allowing an outer `SELECT` to hide nested writes.
- Always dispose read-only PostgreSQL connections when teardown rollback fails due to provider or connection-state errors.
- Make `unique` ignore null values so nullability remains the independent responsibility of `non_null`.
- Defer `denyUnresolvedObjects` until PostgreSQL catalog enrichment in query and equivalence verification, so resolvable relations are not denied before lookup.
- Make `schema_invariant` detect column semantic changes and same-named constraint definition changes in shadow migrations.
- Make `query_succeeds` consume the complete query result server-side so errors in later rows or projected expressions cannot be hidden by an early `EXISTS` result.

### Changed

- Include the project license and attribution files in Windows publish artifacts and SHA-256 checksums, and correct the MCP SDK license and Testcontainers dependency classification. The exact-version SPDX reconciliation remains a separate release gate.

- Retain generated `win-x64` executable and native-parser smoke tooling for maintainer validation of an unreleased binary path; this tooling does not define a public runtime or distribution surface. `SAV_PUBLISHED_WINX64_DIR` remains a test-only override.

- Clarify that `no_new_orphans` is a strict final-state postcondition: any orphan remaining after a migration fails the property, including one that already existed in the base schema.

- Resolve both sides of `verify_equivalence` with one deduplicated PostgreSQL catalog read, preserving side-specific unresolved results.
- Write canonical JSON directly to UTF-8 bytes, reducing allocation while preserving attestation HMAC bytes.
- Map successful PostgreSQL protobuf parse results directly into SQL IR facts, avoiding the JSON intermediary.
- Batch schema snapshot catalog reads to a fixed three PostgreSQL queries per snapshot.
- Batch real-alias read-property checks to reduce PostgreSQL round-trips while preserving independent statements.
- Batch the two bidirectional equivalence diff checks to reduce PostgreSQL round-trips.
- Allow concurrent file I/O for distinct attestations in the file-backed store.

- Batch PostgreSQL catalog lookups when resolving multiple unresolved objects,
  while preserving the single-object query path.
- Reworked public documentation: the README is now a product/install entry
  point, with CLI/MCP and developer references covering architecture,
  algorithms, limits, timeouts, extension points, tests, and licensing.
- Trimmed agent scaffolding (`AGENTS.md`, `docs/plans/`); public docs are product, ADRs, release, and security.
- Dropped `docs/STATUS.md`; baseline is `CHANGELOG.md`, accepted ADRs, and current product documentation.
- Cleaned leftover empty local folders and ignored `.cursor/` / `.ruff_cache/`.
- Rewrote product docs, ADRs, and code comments in a plainer voice (less process jargon).
- Retained the verified read-only transaction for the lifetime of each verification session, resetting it only after a database error or cancellation.
- Made the native-parser publish smoke test independent of concurrent PDB artifacts.

### Security

- Reject real-alias verification of partitioned tables and inheritance parents until policy can account for descendant relations, and resolve unqualified relations only when PostgreSQL would expose them through the active search path.
- Refuse writable PostgreSQL aliases before the DML canary instead of making their proof transaction read-only first.
- Reject real-alias verification of PostgreSQL views and materialized views until catalog enrichment can safely enforce policy on their underlying relations.
- Reject PostgreSQL `SELECT ... INTO` during analysis as an unsupported write-capable construct, and retain its destination relation as a write target.
- Preserve PostgreSQL relation identifier case through parsing, catalog resolution, pair identity, and schema fingerprint lookup so quoted mixed-case names cannot resolve or fingerprint a different lowercase relation.
- Enforce denied-column policy on explicit `INSERT`, `UPDATE`, and `INSERT ... ON CONFLICT DO UPDATE` write targets by retaining their `ResTarget.name` columns in SQL IR.
- Reject real-alias verification when an operator is explicitly outside `pg_catalog` or an unqualified operator name has a visible non-`pg_catalog` definition, preventing custom operator functions from bypassing function policy.
- Updated Testcontainers.PostgreSql to 4.14.0 so its SSH.NET dependency resolves to 2026.0.0, removing the high-severity advisories reported for the previous transitive version.

## [0.1.0-alpha.0] (private/predecessor development history; not a QueryPact public release)

### Added

- CLI and MCP surfaces for query, equivalence, migration, and attestation retrieval.
- Windows `win-x64` publish, checksums, and SPDX SBOM.
- Root layout with source, tests, spikes, release notes, contribution, security, and licensing docs.

### Security

- Read-only targets, alias-based DSN resolution, HMAC-protected redacted attestations, no generic `execute_sql`.

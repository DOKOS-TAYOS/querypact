# Parser spike license & maintenance notes

Date: 2026-07-25
Spike branch: `feat/002-parser-spike`

## pgsqlparser 1.0.0

> This retained engineering evidence records observations from the parser spike. It does not resolve the ASF NOTICE or zlib source-retention questions for public redistribution.

| Field | Evidence |
| --- | --- |
| NuGet | https://www.nuget.org/packages/pgsqlparser/1.0.0 |
| Repo | https://github.com/mysticmind/pgsqlparser-dotnet |
| Wrapper license | MIT (nuspec `license type=expression`) |
| Upstream | `libpg_query` (BSD-3-Clause) + PostgreSQL parser sources (PostgreSQL License) |
| TFMs in package | `net8.0`, `net9.0` (consumed successfully from `net10.0` spike hosts) |
| Native assets | `runtimes/win-x64/native/libpg_query.dll`, `linux-x64/libpg_query.so`, osx-x64/arm64 dylibs |
| Maintenance | NuGet 1.0.0 published 2025-11-04; ~25k downloads observed at spike time |
| Error model | `Result<T>` with structured `Error` (fail-closed friendly) |
| Extra APIs | `Deparse`, `SplitWithParser` / `SplitWithScanner`, `Normalize` / `NormalizeUtility`, `Fingerprint` |
| Load failures | None on win-x64 `dotnet test`/single-file/multi-file; linux-x64 WSL load OK (required `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` due to missing WSL `libicu`, not missing `libpg_query`) |

Historical assessment only; it is not a legal clearance decision. Source redistribution scope remains under review.

## PostgresQuery 0.1.4

| Field | Evidence |
| --- | --- |
| NuGet | https://www.nuget.org/packages/PostgresQuery/0.1.4 |
| Repo | https://github.com/hbirler/pgquery-sharp |
| Wrapper license | BSD-3-Clause |
| Upstream | `libpg_query` + PostgreSQL sources (same family) |
| TFMs in package | `net8.0` only |
| Native assets | `runtimes/win-x64/native/pg_query.dll` (+ `.lib`/`.pdb`), linux-x64/arm64/musl, osx |
| Maintenance | 0.1.x series; NuGet updated 2025-12-08; README warns Windows/macOS builds **untested** |
| Error model | Exceptions on invalid SQL (usable, but less structured than `Result<T>`) |
| Extra APIs | `Normalize` / `NormalizeUtility`, `Fingerprint`, `Split`; **no Deparse** |
| Load failures | None observed in this spike on win-x64/linux-x64 after publish; package still carries untested-Windows disclaimer |

Historical assessment only; it is not a legal clearance decision. Source redistribution scope remains under review.

## Comparison (P15)

The historical spike preferred **pgsqlparser** for clearer fail-closed errors, Deparse, 1.0.0 maturity, and stronger Windows packaging confidence.

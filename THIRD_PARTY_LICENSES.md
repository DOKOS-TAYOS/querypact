# Third-Party Licenses

QueryPact-authored code is MIT-licensed; see [LICENSE](LICENSE) and [NOTICE](NOTICE). This license does not relicense third-party source retained in this repository. Keep the original notices in [`redistribution/`](redistribution/README.md) and the upstream files byte-for-byte.

## Attribution and review status

The exact source locations, revisions, original texts, and checksums for retained native and copied source are recorded in [`redistribution/native-sources.json`](redistribution/native-sources.json) and [`redistribution/package-notices.json`](redistribution/package-notices.json). `scripts/release_licenses.py` and `scripts/release_sbom.py` validate release-time inputs and generated evidence. NuGet metadata alone does not establish which package files are present in an executable or satisfy every source-retention obligation.

### Source redistribution

The retained evidence does not demonstrate a concrete unmet source-redistribution obligation. Two bounded residual uncertainties remain for maintainer assessment and acceptance before source publication: whether an ASF NOTICE applied to the historical Ant revision associated with the retained BouncyCastle BZip2 source, and the scope of zlib's altered-source and marking conditions for the retained zlib 1.1.3 port-source evidence. These uncertainties are not resolved here. This statement is not legal clearance.

The retained BouncyCastle BZip2 sources preserve their original Apache-2.0 headers and Keiron Liddle/Aftex attribution. JCraft source files retain their own BSD conditions. The original zlib 1.1.3 header is separately retained at [`redistribution/upstream/madler/zlib/14763ac7c6c03bca62c39e35c03cf5bfc7728802/referenced/zlib-1.1.3-zlib.h`](redistribution/upstream/madler/zlib/14763ac7c6c03bca62c39e35c03cf5bfc7728802/referenced/zlib-1.1.3-zlib.h). Do not treat the zlib and JCraft texts as interchangeable.

### Binary and package distribution

Separately, any future Windows executable or package distribution requires review of native parser compilation/provenance, effective runtime notices, transitive package contents, ModelContextProtocol's package license transition/contribution/documentation scope, and generated build/test outputs. NuGet metadata alone and this retained source evidence do not establish binary completeness or resolve those release questions. No binary or package legal clearance is claimed.

## Dependencies

| Component | Declared license | Use / notes |
| --- | --- | --- |
| pgsqlparser | MIT | PostgreSQL parser wrapper; native stack includes libpg_query (BSD-3-Clause) and PostgreSQL parser sources (PostgreSQL License). |
| Npgsql | PostgreSQL License | PostgreSQL ADO.NET provider. |
| YamlDotNet | MIT | YAML policy and contract loading; retained upstream attribution applies. |
| System.CommandLine | MIT | CLI host. |
| ModelContextProtocol | Apache-2.0 in package metadata | SDK source retains MIT-to-Apache transition and third-party notices; package scope remains a release-review item. |
| Microsoft.Extensions.* | MIT | Host and dependency injection. |
| Testcontainers.PostgreSql | MIT | Test and ephemeral PostgreSQL workflows; inclusion of every transitive asset in any future executable requires evidence. |
| MinVer | Apache-2.0 | Git-derived versioning. |
| Microsoft.Sbom.Targets | MIT | Build-time SBOM tooling. |
| xUnit, Microsoft.NET.Test.Sdk, coverlet.collector | Apache-2.0 / MIT | Test-only tooling; verify exact package versions during any redistribution. |

Direct versions are pinned in [`Directory.Packages.props`](Directory.Packages.props). Always verify the exact package version and its applicable notices before redistributing it. A generated SBOM complements the original notices; it does not replace them.

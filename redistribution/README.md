# Source redistribution evidence

This directory contains licensing and attribution inputs consumed by `scripts/release_licenses.py`, `scripts/release_sbom.py`, and `scripts/release_bundle.py`. Keep every retained original, source file, license, notice, revision, and checksum intact unless an equivalent reviewed provenance chain is supplied.

- [`native-sources.json`](native-sources.json) identifies immutable upstream locations, revisions, paths, and hashes for native parser attribution.
- [`package-notices.json`](package-notices.json) records exact-version source notices and byte hashes selected by the existing release tooling.
- [`pgsqlparser/`](pgsqlparser/) preserves the native parser and PostgreSQL license/copyright texts.
- [`upstream/`](upstream/) retains original license/notice texts, source snippets and linked evidence used by attribution tooling.

The tools also consume exact restore and bundle evidence generated during a local Windows publish; those outputs are generated for the candidate and are not checked into this source tree. Absolute local paths must remain outside any package.

This evidence is not a legal clearance decision. Open questions include the applicable ASF NOTICE for the retained BouncyCastle BZip2 sources, whether the retained zlib 1.1.3 source evidence invokes its source-retention condition, and attribution scope for package-transition, native compilation, and generated sources. See [`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md). A binary distribution remains blocked independently of source buildability.

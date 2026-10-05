# Windows QueryPact executable verification (maintainer tooling)

This is maintainer/development tooling for an **unreleased binary path**. It
does not define a supported public runtime or distribution surface. Windows x64
source restore/build/test compatibility is validated, but executable runtime
support has not been established. No prebuilt QueryPact binaries are
distributed; binary distribution remains blocked.

Only after the binary-release gate is separately resolved should maintainers
build from an exact source candidate and verify a generated `querypact.exe`.
Record the SDK, source commit, build output, and test results. Do not treat a CI
artifact as a public release. `WINDOWS BINARY RELEASE` and
`publicReleaseGate=BLOCKED` remain unchanged.

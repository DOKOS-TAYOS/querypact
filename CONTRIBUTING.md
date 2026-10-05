# Contributing to QueryPact

Thanks for your interest in contributing. By participating, you agree to follow
the [Code of Conduct](CODE_OF_CONDUCT.md).

## Project layout

The git repository root hosts the product, community / legal files, and CI:

```text
src/                 # production projects
tests/               # unit, integration, and security tests
docs/                # product, architecture, release, and security docs
spikes/              # exploratory parser evidence
```

Run `dotnet` commands from the repository root. Start with [`README.md`](README.md)
and the product docs under [`docs/product/`](docs/product/) before changing code.

## Language

- Public documentation, code, APIs, commit messages, and PR descriptions:
  **English**
- Security reports and private maintainer contact may use Spanish or English

## Before you start

1. Read the [security model](docs/product/02_SECURITY_MODEL.md) and the
   [platform-support policy](README.md#platform-support).
2. Check [`CHANGELOG.md`](CHANGELOG.md) and accepted ADRs under `docs/adr/` for
   the current product baseline.
3. Prefer small, focused PRs. Do not expand scope beyond the issue or request.
4. Do not weaken fail-closed security behavior, redactors, or tests to make a
   change pass.

## Development setup

Requirements:

- .NET SDK matching [`global.json`](global.json)
- PostgreSQL tooling as needed for local verification / Testcontainers
- Linux x64 is the supported platform for running QueryPact from source.
- Windows x64 source restore/build/test compatibility is validated; Windows
  executable runtime and distribution are not a supported public release
  surface. macOS is unverified.
- No prebuilt QueryPact binaries are distributed. Windows publishing scripts
  are maintainer/development tooling for an unreleased binary path.

Typical gates (from the repository root):

```bash
dotnet restore
dotnet build -c Release
dotnet run --project src/Sav.Host/Sav.Host.csproj -c Release -- --help
```

Also run the UTF-8 / no-mojibake check used in CI when you touch docs:

```powershell
./scripts/Test-NoMojibake.ps1
```

## Pull requests

1. Fork (or branch) from `main`.
2. Keep commits small and descriptive.
3. Include tests for behavior changes; never delete or weaken tests to green CI.
4. Update [`CHANGELOG.md`](CHANGELOG.md) for user-visible or security-relevant
   changes; add or amend an ADR when the decision is architectural.
5. Open a PR against `main` and fill in the pull request template.

## Security issues

Do **not** file public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under the [MIT License](LICENSE). You retain
copyright to your contributions; by submitting a PR you grant permission to
distribute them under that license.

## Citation

If you use QueryPact in academic or industry work, see [CITATION.cff](CITATION.cff).

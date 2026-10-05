# Security Policy

## Supported versions

Security fixes are accepted for the latest commit on `main` and for the most
recent tagged release (when tags exist). Older releases may not receive
backports unless a release branch is explicitly maintained.

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public GitHub issue
for vulnerabilities that could expose credentials, enable policy bypass, leak
row payloads, or weaken fail-closed behavior.

Preferred channels (pick one):

1. **GitHub Security Advisories** for this repository (private report), if
   available for the repo.
2. **Email:** [alejandro.mata.ali@gmail.com](mailto:alejandro.mata.ali@gmail.com)

Include, when possible:

- Affected version / commit SHA
- Reproduction steps or a minimal PoC
- Impact (confidentiality, integrity, availability, attestation trust)
- Whether the issue is already public

You should receive an acknowledgement within **7 days**. We will coordinate a
fix timeline and credit (if you want it) before any public disclosure.

## Product security expectations

QueryPact fails closed on untrusted agent-proposed SQL. Operators
should still:

- Use dedicated read-only PostgreSQL roles and the documented `sav_ro_probe`
- Keep `SAV_ATTESTATION_HMAC_KEY` secret and sufficiently strong
- Treat aliases / DSNs in local config as sensitive
- Read [`docs/product/02_SECURITY_MODEL.md`](docs/product/02_SECURITY_MODEL.md)

## Out of scope for private reports

General feature requests, documentation typos, and non-security bugs belong in
public issues (see [CONTRIBUTING.md](CONTRIBUTING.md)).

# Security Policy

## Responsible Use

WizIntel is defensive, passive-first software for authorized security analysis. Do not use it for harassment, doxxing, phishing, credential theft, exploitation, brute force, intrusion, evasion, bypassing authentication, bypassing rate limits, or any other unauthorized activity.

## Secret Redaction

WizIntel v1 does not store raw secret values from TruffleHog findings. Secret findings retain metadata such as detector type, source file, line number when available, verification status, and a non-reversible fingerprint. Reports use `redacted_value` by default.

Email targets and findings are masked by default in JSON, CSV, HTML, and the
experimental read-only API. This policy also covers recognizable email text in
exported metadata and nested evidence. Original values remain in the local case
store; report commands can explicitly export them with `--include-sensitive` to
separate `.full` files. The API has no full-fidelity export option and no access
control; it is intended only for trusted local use. See [usage](docs/usage.md) for
format differences, migration steps, and masking limits.

Sherlock findings are labeled as unverified public profile matches and require analyst validation.

## Reporting Vulnerabilities

Report vulnerabilities privately to the project maintainers. Include:

- A concise description.
- Affected version or commit.
- Reproduction steps.
- Security impact.
- Suggested remediation when available.

Do not include live third-party secrets, unauthorized scan data, or exploit payloads in reports.

## Scope And Authorization Warning

Every scan must be tied to an explicit scope object and authorization assertion. Active scanning is not implemented in v1. Only scan assets, repositories, accounts, and organizations you are authorized to assess.

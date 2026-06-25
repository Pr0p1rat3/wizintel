# WizIntel

Passive OSINT and external exposure intelligence for security analysts.

WizIntel is a defensive, passive-first orchestration tool for analyst workflows. It wraps trusted OSINT tools, normalizes and deduplicates their findings, applies deterministic risk scoring, stores local case results in SQLite, and generates analyst-ready HTML, CSV, and JSON reports.

## What WizIntel Is

- A passive-first OSINT orchestration CLI.
- A local case store for external exposure findings.
- A wrapper for tools such as theHarvester, subfinder, Amass passive enum, Sherlock, and TruffleHog.
- A report generator that redacts sensitive values by default.

## What WizIntel Is Not

- Not an exploitation framework.
- Not an active scanner in v1.
- Not a credential theft, phishing, brute force, harassment, doxxing, or intrusion tool.
- Not a bypass mechanism for rate limits, CAPTCHAs, authentication, or access controls.

## Safety Model

WizIntel requires a scan scope object for every scan, defaults to passive mode, and refuses active mode in v1. The CLI shows an authorization banner on initialization and before scans. Sherlock results are labeled as unverified public profile matches. Secret findings are redacted by default and raw credential values are not stored by WizIntel v1.

Use WizIntel only for assets, repositories, accounts, and organizations you are authorized to assess.

# Buy me a cuban C0ff33 ^__^

    BTC: bc1qtv8j0l887frldav7k8sdz8nz3n4y6shv7cvnx7
    ETH: 0x014603d2F6B2D17AECBa2Df7ac3eeAB667bf068d


## Installation

```bash
python3 -m pip install -e ".[dev]"
```

Python 3.11 or newer is required.

## External Tool Notes

WizIntel checks for, but does not require, the external OSINT binaries at install time:

- `theHarvester`
- `subfinder`
- `amass`
- `sherlock`
- `trufflehog`
- `spiderfoot`

Missing tools produce warnings and do not crash the whole scan.

## Quickstart

```bash
wizintel init
wizintel tools check
wizintel scan domain example.com --passive
wizintel report latest --html
```

More examples:

```bash
wizintel scan email user@example.com --passive
wizintel scan username somehandle --passive
wizintel scan github https://github.com/org/repo --passive
wizintel report case case_20260624_120000_abcd1234 --json
wizintel report case case_20260624_120000_abcd1234 --csv
```

Case output is written under:

```text
./data/cases/<case_id>/
  findings.json
  findings.csv
  report.html
  scan.log
```

## Report Screenshots

Screenshots will be added after the first public UI polish pass.

## Development

```bash
make install
make lint
make typecheck
make test
```

## Roadmap

- Expand parser coverage for tool version differences.
- Add optional analyst review and severity override workflow.
- Add richer SpiderFoot integration while preserving passive defaults.
- Add an experimental read-only API UI for local scan review.
- Add import/export bundles for case handoff.

## Legal And Authorization Disclaimer

Only use WizIntel where you have clear authorization. You are responsible for complying with laws, contracts, platform terms, and internal rules of engagement.

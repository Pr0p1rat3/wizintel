# Collectors

## theHarvester

Collects public emails, names, hosts, and subdomains where supported. Domain scans use the requested domain. Email scans derive the domain portion for supported passive lookup.

Command shape:

```bash
theHarvester -d example.com -b all -f <output_base>
```

## subfinder

Passive subdomain discovery.

```bash
subfinder -silent -d example.com -json
```

## Amass

Passive external asset discovery only.

```bash
amass enum -passive -d example.com -json <output_file>
```

## Sherlock

Public username profile discovery. Results are labeled as unverified public profile matches.

```bash
sherlock username --print-found --json <output_file>
```

## TruffleHog

Public repository secret exposure checks. Secret values are redacted and raw values are not stored.

```bash
trufflehog github --repo https://github.com/org/repo --json
```

## SpiderFoot

Disabled by default in v1. The placeholder exists so a future passive-only connector can be added without changing the orchestration model.

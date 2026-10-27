# Usage

Initialize local configuration and storage:

```bash
wizintel init
```

Check external tools:

```bash
wizintel tools check
```

Run passive scans:

```bash
wizintel scan domain example.com --passive
wizintel scan email user@example.com --passive
wizintel scan username somehandle --passive
wizintel scan github https://github.com/org/repo --passive
```

Generate reports:

```bash
wizintel report latest --html
wizintel report case <case_id> --json
wizintel report case <case_id> --csv
wizintel report case <case_id> --html
```

### Redaction and full-fidelity exports

Automatic scan reports and regenerated reports mask email targets and email findings by
default. JSON keeps its existing scan/finding structure, but both `value` and
`redacted_value` contain the display-safe value. Default CSV columns are unchanged.
The export policy also masks recognizable email addresses in sources, tags, scope
notes, output paths, and nested evidence keys and values. It recognizes ordinary
email text and `%40` in place of `@` in URLs. Domain names and the first local-part
character remain visible, for example `alice@example.com` becomes `a***@example.com`.
This is masking, not anonymization or a general personal-data/secret scrubber; unusual
encodings, obfuscation, names, and other identifiers still need analyst review.

Original email values remain in the local SQLite case store for investigation,
deduplication, and explicit export. Exporting never mutates the stored case. Finding
IDs remain available in JSON/API results to distinguish addresses that mask identically.
If evidence keys collide after masking, numbered suffixes preserve all entries.

To deliberately export original stored values:

```bash
wizintel report case <case_id> --json --csv --html --include-sensitive
wizintel report latest --json --include-sensitive
```

This opt-in applies only to that command. It prints a sensitive-export notice and
writes `findings.full.json`, `findings.full.csv`, and/or `report.full.html` alongside
the masked reports. Existing masked reports are preserved. JSON records
`metadata.redaction_mode` (`redacted` or `full-fidelity`); HTML includes a visible
mode notice. Full-fidelity JSON includes all stored fields; HTML remains a summary;
CSV remains a findings table and adds a `value` column for the original value while
retaining `redacted_value`. CSV has no scan target or nested evidence in either mode.
Only JSON is a complete structured export. Secrets already discarded by collectors
cannot be recovered in any export mode.

Python callers can pass the keyword-only `include_sensitive=True` to the report
builders/writers or `regenerate_report`. Direct writers use the caller's output
path; `regenerate_report` chooses the separate `.full` filename automatically.

The experimental `GET /scans` and `GET /scans/{scan_id}` endpoints always apply the
default masking policy and keep their existing response shapes. They offer no
full-fidelity switch. The API has no authentication or authorization; keep it bound
to loopback in a trusted local environment. Masking does not make it safe to expose
case metadata or evidence publicly.

Existing report files are not rewritten automatically. Regenerate each case's
reports after upgrading, for example:

```bash
wizintel report case <case_id> --json --csv --html
```

The database, collector-created files in `raw/`, logs, and `.full` exports are local
investigation material and may contain sensitive data. The export policy does not
rewrite them, rename directories, or clean up copies of old reports. Share individual
reviewed reports rather than entire case directories.

Active mode is refused in v1:

```bash
wizintel scan domain example.com --active
```

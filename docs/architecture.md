# Architecture

WizIntel is organized as a CLI-first Python package under `src/wizintel`.

- `cli.py` exposes Typer commands.
- `orchestrator.py` coordinates scan cases, collectors, normalization, scoring, storage, and reports.
- `collectors/` contains wrappers for external OSINT tools. Collectors build list-argument subprocess commands and never use `shell=True`.
- `schemas/` contains Pydantic v2 models for targets, scans, findings, collectors, and reports.
- `normalizers/` provides canonicalization and deduplication helpers.
- `db/` stores local cases in SQLite through SQLAlchemy.
- `reports/` writes JSON, CSV, and Jinja2 HTML reports.
- `api/` contains an experimental read-only FastAPI scaffold.

The v1 control flow is:

1. CLI builds an explicit `Target` scope object.
2. Orchestrator enforces authorization and passive mode.
3. Enabled collectors run if their target type is supported and their binary exists.
4. Findings are normalized, deduplicated, scored, and saved.
5. Reports are written under `./data/cases/<case_id>/`.

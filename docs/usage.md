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

Active mode is refused in v1:

```bash
wizintel scan domain example.com --active
```

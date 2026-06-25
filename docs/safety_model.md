# Safety Model

WizIntel is built around defensive defaults:

- Passive mode is the default.
- Active scanning is not implemented in v1.
- Every scan creates an explicit `Target` scope object.
- The CLI prints an authorization banner before scans.
- Scan logs record target type, redacted target where appropriate, collectors, timestamp, passive mode, and output path.
- Secrets are redacted by default.
- Raw credentials are not stored in v1.
- The code does not implement exploitation, credential theft, evasion, brute force, phishing, or intrusion logic.
- The code does not bypass rate limits, CAPTCHAs, authentication, or access controls.
- Sherlock findings are unverified public profile matches.

Analysts remain responsible for authorization, platform terms, and rules of engagement.

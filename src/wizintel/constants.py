"""Project constants."""

from __future__ import annotations

APP_NAME = "WizIntel"
TAGLINE = "Passive OSINT and external exposure intelligence for security analysts."
VERSION = "0.1.0"

DEFAULT_CONFIG_FILE = "config.yml"
DEFAULT_DATA_DIR = "./data"
DEFAULT_DB_NAME = "wizintel.db"

SUPPORTED_TOOL_BINARIES = {
    "theharvester": "theHarvester",
    "subfinder": "subfinder",
    "amass": "amass",
    "sherlock": "sherlock",
    "trufflehog": "trufflehog",
    "spiderfoot": "spiderfoot",
}

FINDING_TYPES = (
    "domain",
    "subdomain",
    "email",
    "username_profile",
    "host",
    "ip",
    "secret_exposure",
    "metadata",
)

SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCE_LEVELS = ("low", "medium", "high")

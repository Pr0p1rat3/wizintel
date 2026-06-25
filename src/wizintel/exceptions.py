"""Custom exceptions for WizIntel."""

from __future__ import annotations


class WizIntelError(Exception):
    """Base exception for project-specific failures."""


class AuthorizationError(WizIntelError):
    """Raised when scan authorization requirements are not met."""


class ActiveScanNotSupportedError(WizIntelError):
    """Raised when active scanning is requested in v1."""


class CollectorError(WizIntelError):
    """Raised for collector-specific failures."""


class ConfigurationError(WizIntelError):
    """Raised for invalid configuration."""

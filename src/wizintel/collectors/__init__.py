"""Collector implementations."""

from wizintel.collectors.base import BaseCollector
from wizintel.collectors.registry import collectors_for_target, get_default_collectors

__all__ = ["BaseCollector", "collectors_for_target", "get_default_collectors"]

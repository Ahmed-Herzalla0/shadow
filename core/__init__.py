"""SHADOW Core Module - Database Layer Only

The scoring and orchestration logic has moved to:
- decision/decision.py - Scoring and ranking
- orchestrator.py - Module execution and state

This module only contains database operations.
"""

from .db import Asset, Database, Endpoint, Finding, Service

__all__ = [
    "Database",
    "Asset",
    "Service",
    "Endpoint",
    "Finding",
]

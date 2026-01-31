#!/usr/bin/env python3
"""
SHADOW - Output Schemas

Pydantic models for validated, typed output structures.
These schemas ensure consistent, machine-consumable output formats.

Author: SHADOW Team
License: MIT
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

class Priority(str, Enum):
    """Target priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOISE = "noise"


class Action(str, Enum):
    """Recommended actions"""
    RCE_VERIFY = "rce-verify"
    SQLI_TEST = "sqli-test"
    LFI_TEST = "lfi-test"
    SSRF_TEST = "ssrf-test"
    XSS_TEST = "xss-test"
    IDOR_TEST = "idor-test"
    GRAPHQL_INTROSPECT = "graphql-introspect"
    ADMIN_ACCESS_CHECK = "admin-access-check"
    INFO_LEAK_VERIFY = "info-leak-verify"
    MANUAL_REVIEW = "manual-review"
    DEEP_SCAN = "deep-scan"
    TARGETED_SCAN = "targeted-scan"
    MONITOR = "monitor"
    IGNORE = "ignore"


class Scope(str, Enum):
    """Scan scopes"""
    XSS = "xss"
    API = "api"
    JS = "js"
    FULL = "full"


# ═══════════════════════════════════════════════════════════════════════════════
# CORE SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class RankedTarget(BaseModel):
    """A ranked and scored target endpoint"""

    url: str = Field(..., description="Full URL of the target")
    domain: str = Field(..., description="Domain name")
    path: str = Field(default="/", description="URL path")
    params: Dict[str, str] = Field(default_factory=dict, description="URL parameters")
    score: int = Field(..., ge=0, description="Calculated score (higher = more interesting)")
    priority: str = Field(..., description="Priority level (critical/high/medium/low/noise)")
    action: str = Field(..., description="Recommended action to take")
    reasons: List[str] = Field(default_factory=list, description="Reasons for the score")
    tags: List[str] = Field(default_factory=list, description="Vulnerability category tags")
    source: str = Field(default="", description="Module that discovered this target")

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        valid = {"critical", "high", "medium", "low", "noise"}
        if v.lower() not in valid:
            raise ValueError(f"Priority must be one of {valid}")
        return v.lower()


class TargetsReport(BaseModel):
    """Full targets ranked report"""

    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    target: str = Field(..., description="Root target domain")
    scope: str = Field(default="xss", description="Scan scope used")
    total_scored: int = Field(..., ge=0, description="Total number of targets scored")
    targets: List[RankedTarget] = Field(default_factory=list, description="Ranked targets")


class ModuleResult(BaseModel):
    """Result from a single module execution"""

    module_name: str = Field(..., description="Name of the module")
    success: bool = Field(..., description="Whether the module succeeded")
    exit_code: int = Field(..., description="Process exit code")
    duration_seconds: float = Field(..., ge=0, description="Execution duration")
    output_file: Optional[str] = Field(None, description="Path to output JSONL")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    lines_produced: int = Field(default=0, ge=0, description="Number of JSONL lines")


class ScanSummary(BaseModel):
    """Summary of a complete scan"""

    target: str
    scope: str
    started_at: str
    completed_at: str
    duration_seconds: float
    modules_run: int
    modules_succeeded: int
    modules_failed: int
    total_targets_scored: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    top_target: Optional[RankedTarget] = None


class ScanConfig(BaseModel):
    """Scan configuration"""

    target: str = Field(..., description="Target domain")
    scope: Scope = Field(default=Scope.XSS, description="Scan scope")
    output_dir: str = Field(default="output", description="Output directory")
    resume: bool = Field(default=False, description="Resume from previous state")
    debug: bool = Field(default=False, description="Enable debug logging")
    allow_destructive: bool = Field(default=False, description="Allow destructive modules")
    confirm_legal: bool = Field(default=False, description="Confirmed legal authorization")
    timeout: int = Field(default=300, ge=1, description="Default timeout per module")
    retries: int = Field(default=2, ge=0, description="Number of retries per module")


# ═══════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainEntry(BaseModel):
    """A discovered subdomain"""

    subdomain: str = Field(..., description="Subdomain (e.g., api.example.com)")
    domain: str = Field(..., description="Root domain (e.g., example.com)")
    source: str = Field(..., description="Discovery source (e.g., subfinder)")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    type: Literal["subdomain"] = "subdomain"

    @field_validator("subdomain")
    @classmethod
    def validate_subdomain(cls, v: str) -> str:
        v = v.lower().strip()
        if not v or " " in v:
            raise ValueError("Invalid subdomain format")
        return v


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP PROBE SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPProbeEntry(BaseModel):
    """HTTP probe result"""

    url: str
    status_code: int = Field(..., ge=0, le=999)
    content_length: int = Field(default=0, ge=0)
    title: str = Field(default="")
    technology: List[str] = Field(default_factory=list)
    server: str = Field(default="")
    redirect_url: Optional[str] = None
    source: str = Field(default="httpx")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    type: Literal["http_probe"] = "http_probe"


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class EndpointEntry(BaseModel):
    """A discovered endpoint"""

    url: str
    domain: str
    path: str
    method: str = Field(default="GET")
    params: Dict[str, str] = Field(default_factory=dict)
    content_type: str = Field(default="")
    source: str = Field(default="")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    type: Literal["endpoint"] = "endpoint"


# ═══════════════════════════════════════════════════════════════════════════════
# FINDING SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

class FindingEntry(BaseModel):
    """A security finding"""

    url: str
    finding_type: str = Field(..., description="Type (e.g., xss, sqli, ssrf)")
    severity: str = Field(default="info", description="Severity level")
    title: str
    evidence: str = Field(default="")
    template_id: Optional[str] = Field(None, description="Nuclei template ID")
    confirmed: bool = Field(default=False)
    source: str = Field(default="")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    type: Literal["finding"] = "finding"

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"info", "low", "medium", "high", "critical"}
        if v.lower() not in valid:
            raise ValueError(f"Severity must be one of {valid}")
        return v.lower()

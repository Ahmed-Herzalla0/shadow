"""
SHADOW v6 - JSON Schemas for Module Outputs

Every module produces normalized JSON output.
Schemas ensure consistency and enable automation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import json


# ═══════════════════════════════════════════════════════════════════════════════
# BASE SCHEMA
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ModuleOutput:
    """Base schema for all module outputs"""
    module: str                          # Module name (e.g., "01_intel")
    target: str                          # Target domain
    timestamp: str                       # ISO timestamp
    success: bool = True                 # Did module complete successfully
    error: Optional[str] = None          # Error message if failed
    duration_seconds: float = 0.0        # How long it took
    data: Dict[str, Any] = field(default_factory=dict)  # Module-specific data
    
    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ModuleOutput':
        data = json.loads(json_str)
        return cls(**data)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 01: INTEL
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ASNInfo:
    """ASN information"""
    number: str
    name: str
    country: str
    cidr_ranges: List[str] = field(default_factory=list)


@dataclass
class WhoisInfo:
    """WHOIS information"""
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    organization: Optional[str] = None


@dataclass
class IntelOutput:
    """Schema for 01_intel module output"""
    asn: Optional[ASNInfo] = None
    whois: Optional[WhoisInfo] = None
    ip_ranges: List[str] = field(default_factory=list)
    related_domains: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "asn": self.asn.__dict__ if self.asn else None,
            "whois": self.whois.__dict__ if self.whois else None,
            "ip_ranges": self.ip_ranges,
            "related_domains": self.related_domains
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 02: SUBDOMAINS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Subdomain:
    """A discovered subdomain"""
    name: str
    source: str  # Which tool found it
    is_wildcard: bool = False


@dataclass
class SubdomainsOutput:
    """Schema for 02_subdomains module output"""
    total_found: int = 0
    unique_count: int = 0
    subdomains: List[Subdomain] = field(default_factory=list)
    sources_used: List[str] = field(default_factory=list)
    wildcards: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_found": self.total_found,
            "unique_count": self.unique_count,
            "subdomains": [s.__dict__ for s in self.subdomains],
            "sources_used": self.sources_used,
            "wildcards": self.wildcards
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 03: DNS
# ═══════════════════════════════════════════════════════════════════════════════

class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"


@dataclass
class DNSRecord:
    """A DNS record"""
    subdomain: str
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class DNSOutput:
    """Schema for 03_dns module output"""
    resolved_count: int = 0
    records: List[DNSRecord] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    cnames: Dict[str, str] = field(default_factory=dict)  # subdomain -> cname
    potential_takeovers: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "resolved_count": self.resolved_count,
            "records": [r.__dict__ for r in self.records],
            "ips": self.ips,
            "cnames": self.cnames,
            "potential_takeovers": self.potential_takeovers
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 05: HTTP
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HTTPHost:
    """An HTTP host"""
    url: str
    status_code: int
    title: str = ""
    content_length: int = 0
    technologies: List[str] = field(default_factory=list)
    server: str = ""
    content_type: str = ""
    redirect_url: str = ""
    tls_version: str = ""
    response_time_ms: int = 0


@dataclass
class HTTPOutput:
    """Schema for 05_http module output"""
    alive_count: int = 0
    hosts: List[HTTPHost] = field(default_factory=list)
    technologies_found: Dict[str, int] = field(default_factory=dict)  # tech -> count
    waf_detected: Optional[str] = None
    waf_confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "alive_count": self.alive_count,
            "hosts": [h.__dict__ for h in self.hosts],
            "technologies_found": self.technologies_found,
            "waf_detected": self.waf_detected,
            "waf_confidence": self.waf_confidence
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 06: CONTENT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DiscoveredPath:
    """A discovered path/file"""
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    is_interesting: bool = False
    category: str = ""  # admin, backup, config, etc.


@dataclass
class ContentOutput:
    """Schema for 06_content module output"""
    paths_found: int = 0
    paths: List[DiscoveredPath] = field(default_factory=list)
    interesting_paths: List[DiscoveredPath] = field(default_factory=list)
    admin_panels: List[str] = field(default_factory=list)
    backup_files: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "paths_found": self.paths_found,
            "paths": [p.__dict__ for p in self.paths],
            "interesting_paths": [p.__dict__ for p in self.interesting_paths],
            "admin_panels": self.admin_panels,
            "backup_files": self.backup_files,
            "config_files": self.config_files
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 07: JS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class JSSecret:
    """A secret found in JavaScript"""
    type: str
    value: str
    file: str
    line: int
    sensitivity: str  # low, medium, high, critical


@dataclass
class JSEndpoint:
    """An endpoint found in JavaScript"""
    url: str
    method: str
    source_file: str
    requires_auth: bool = False


@dataclass
class JSOutput:
    """Schema for 07_js module output"""
    files_analyzed: int = 0
    endpoints_found: int = 0
    secrets_found: int = 0
    endpoints: List[JSEndpoint] = field(default_factory=list)
    secrets: List[JSSecret] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_analyzed": self.files_analyzed,
            "endpoints_found": self.endpoints_found,
            "secrets_found": self.secrets_found,
            "endpoints": [e.__dict__ for e in self.endpoints],
            "secrets": [s.__dict__ for s in self.secrets],
            "frameworks": self.frameworks,
            "source_maps": self.source_maps,
            "domains": self.domains
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 08: PARAMS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Parameter:
    """A discovered parameter"""
    name: str
    url: str
    method: str = "GET"
    reflects: bool = False
    vuln_type: str = ""  # xss, sqli, ssrf, idor, etc.


@dataclass
class ParamsOutput:
    """Schema for 08_params module output"""
    urls_found: int = 0
    params_found: int = 0
    urls: List[str] = field(default_factory=list)
    parameters: List[Parameter] = field(default_factory=list)
    xss_candidates: List[str] = field(default_factory=list)
    sqli_candidates: List[str] = field(default_factory=list)
    ssrf_candidates: List[str] = field(default_factory=list)
    idor_candidates: List[str] = field(default_factory=list)
    lfi_candidates: List[str] = field(default_factory=list)
    redirect_candidates: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "urls_found": self.urls_found,
            "params_found": self.params_found,
            "urls": self.urls[:100],  # Limit for JSON size
            "parameters": [p.__dict__ for p in self.parameters[:100]],
            "xss_candidates": self.xss_candidates,
            "sqli_candidates": self.sqli_candidates,
            "ssrf_candidates": self.ssrf_candidates,
            "idor_candidates": self.idor_candidates,
            "lfi_candidates": self.lfi_candidates,
            "redirect_candidates": self.redirect_candidates
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 09: VULN
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Vulnerability:
    """A discovered vulnerability"""
    name: str
    severity: str  # info, low, medium, high, critical
    url: str
    template: str = ""
    description: str = ""
    matcher: str = ""
    evidence: str = ""
    cve: str = ""
    cvss: float = 0.0


@dataclass
class VulnOutput:
    """Schema for 09_vuln module output"""
    total_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    confirmed: List[Vulnerability] = field(default_factory=list)
    potential: List[Vulnerability] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_found": self.total_found,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "confirmed": [v.__dict__ for v in self.confirmed],
            "potential": [v.__dict__ for v in self.potential]
        }


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE RESULT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PipelineResult:
    """Complete result of a SHADOW scan"""
    target: str
    started_at: str
    completed_at: str
    duration_seconds: float
    
    intel: Optional[IntelOutput] = None
    subdomains: Optional[SubdomainsOutput] = None
    dns: Optional[DNSOutput] = None
    http: Optional[HTTPOutput] = None
    content: Optional[ContentOutput] = None
    js: Optional[JSOutput] = None
    params: Optional[ParamsOutput] = None
    vulns: Optional[VulnOutput] = None
    
    modules_executed: List[str] = field(default_factory=list)
    modules_skipped: Dict[str, str] = field(default_factory=dict)
    
    score: int = 0
    priority: str = "low"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "intel": self.intel.to_dict() if self.intel else None,
            "subdomains": self.subdomains.to_dict() if self.subdomains else None,
            "dns": self.dns.to_dict() if self.dns else None,
            "http": self.http.to_dict() if self.http else None,
            "content": self.content.to_dict() if self.content else None,
            "js": self.js.to_dict() if self.js else None,
            "params": self.params.to_dict() if self.params else None,
            "vulns": self.vulns.to_dict() if self.vulns else None,
            "modules_executed": self.modules_executed,
            "modules_skipped": self.modules_skipped,
            "score": self.score,
            "priority": self.priority
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

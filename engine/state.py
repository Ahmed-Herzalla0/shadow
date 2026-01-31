"""
SHADOW v6 - State Machine

Every target has a state that evolves as we gather intelligence.
Modules read and update state. Decisions are based on state.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path
from enum import Enum


class TargetPhase(Enum):
    """Current phase in the reconnaissance pipeline"""
    INIT = "init"
    RECON = "recon"
    ENUMERATION = "enumeration"
    ANALYSIS = "analysis"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    COMPLETE = "complete"


class WAFType(Enum):
    """Known WAF types with their impact on scanning"""
    NONE = "none"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    MODSECURITY = "modsecurity"
    F5 = "f5"
    UNKNOWN = "unknown"


@dataclass
class AuthInfo:
    """Authentication surface information"""
    has_login: bool = False
    has_oauth: bool = False
    has_sso: bool = False
    has_api_keys: bool = False
    has_jwt: bool = False
    login_endpoints: List[str] = field(default_factory=list)
    oauth_providers: List[str] = field(default_factory=list)
    session_type: Optional[str] = None  # cookie, token, etc.


@dataclass
class APIInfo:
    """API surface information"""
    detected: bool = False
    type: Optional[str] = None  # rest, graphql, grpc, soap
    endpoints_count: int = 0
    has_swagger: bool = False
    has_graphql_introspection: bool = False
    versions: List[str] = field(default_factory=list)
    interesting_endpoints: List[str] = field(default_factory=list)


@dataclass
class JSInfo:
    """JavaScript intelligence"""
    has_js: bool = False
    frameworks: List[str] = field(default_factory=list)  # react, angular, vue
    endpoints_found: int = 0
    secrets_found: int = 0
    api_keys_found: int = 0
    interesting_flows: List[Dict[str, Any]] = field(default_factory=list)
    source_maps: bool = False


@dataclass
class ParamsInfo:
    """Parameter surface"""
    total_count: int = 0
    with_reflection: int = 0
    interesting_params: List[str] = field(default_factory=list)
    sqli_candidates: List[str] = field(default_factory=list)
    xss_candidates: List[str] = field(default_factory=list)
    ssrf_candidates: List[str] = field(default_factory=list)
    idor_candidates: List[str] = field(default_factory=list)


@dataclass 
class Fingerprint:
    """Target fingerprint"""
    technologies: List[str] = field(default_factory=list)
    server: Optional[str] = None
    cms: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    cdn: Optional[str] = None
    hosting: Optional[str] = None


@dataclass
class VulnHints:
    """Vulnerability indicators found during recon"""
    cors_misconfigured: bool = False
    open_redirect_likely: bool = False
    path_traversal_likely: bool = False
    ssrf_likely: bool = False
    sqli_likely: bool = False
    xss_likely: bool = False
    idor_likely: bool = False
    admin_panel: bool = False
    debug_mode: bool = False
    backup_files: bool = False
    git_exposed: bool = False
    env_exposed: bool = False
    error_messages: bool = False
    stack_traces: bool = False


@dataclass
class TargetState:
    """
    Complete state of a target.
    This is the single source of truth for all decisions.
    """
    # Identity
    domain: str
    base_path: str
    
    # Phase tracking
    phase: TargetPhase = TargetPhase.INIT
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Core intelligence
    alive_hosts: List[str] = field(default_factory=list)
    subdomains_count: int = 0
    
    # WAF detection
    waf: WAFType = WAFType.NONE
    waf_confidence: float = 0.0
    
    # Attack surface
    auth: AuthInfo = field(default_factory=AuthInfo)
    api: APIInfo = field(default_factory=APIInfo)
    js: JSInfo = field(default_factory=JSInfo)
    params: ParamsInfo = field(default_factory=ParamsInfo)
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    vuln_hints: VulnHints = field(default_factory=VulnHints)
    
    # Scoring
    score: int = 0
    priority: str = "low"  # low, medium, high, critical
    
    # Noise tracking
    rate_limited: bool = False
    blocked: bool = False
    noise_pauses: int = 0
    
    # Custom tags
    tags: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    # Module execution history
    modules_executed: List[str] = field(default_factory=list)
    modules_skipped: Dict[str, str] = field(default_factory=dict)  # module: reason
    
    def update_timestamp(self):
        """Update the modified timestamp"""
        self.updated_at = datetime.now().isoformat()
    
    def add_note(self, note: str):
        """Add a note with timestamp"""
        self.notes.append(f"[{datetime.now().strftime('%H:%M')}] {note}")
        self.update_timestamp()
    
    def add_tag(self, tag: str):
        """Add a tag if not exists"""
        if tag not in self.tags:
            self.tags.append(tag)
            self.update_timestamp()
    
    def mark_module_executed(self, module: str):
        """Mark a module as executed"""
        if module not in self.modules_executed:
            self.modules_executed.append(module)
            self.update_timestamp()
    
    def mark_module_skipped(self, module: str, reason: str):
        """Mark a module as skipped with reason"""
        self.modules_skipped[module] = reason
        self.update_timestamp()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        # Convert enums to strings
        data['phase'] = self.phase.value
        data['waf'] = self.waf.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TargetState':
        """Create from dictionary"""
        # Convert strings back to enums
        data['phase'] = TargetPhase(data.get('phase', 'init'))
        data['waf'] = WAFType(data.get('waf', 'none'))
        
        # Convert nested objects
        data['auth'] = AuthInfo(**data.get('auth', {}))
        data['api'] = APIInfo(**data.get('api', {}))
        data['js'] = JSInfo(**data.get('js', {}))
        data['params'] = ParamsInfo(**data.get('params', {}))
        data['fingerprint'] = Fingerprint(**data.get('fingerprint', {}))
        data['vuln_hints'] = VulnHints(**data.get('vuln_hints', {}))
        
        return cls(**data)
    
    def summary(self) -> str:
        """Human-readable summary"""
        lines = [
            f"═══ {self.domain} ═══",
            f"Phase: {self.phase.value} | Score: {self.score} | Priority: {self.priority}",
            f"Subdomains: {self.subdomains_count} | Alive: {len(self.alive_hosts)}",
            f"WAF: {self.waf.value} ({self.waf_confidence:.0%})",
            "",
            "Attack Surface:",
            f"  • Auth: {'✓' if self.auth.has_login else '✗'} Login | {'✓' if self.auth.has_oauth else '✗'} OAuth | {'✓' if self.auth.has_jwt else '✗'} JWT",
            f"  • API: {'✓' if self.api.detected else '✗'} ({self.api.type or 'none'}) | {self.api.endpoints_count} endpoints",
            f"  • JS: {self.js.endpoints_found} endpoints | {self.js.secrets_found} secrets",
            f"  • Params: {self.params.total_count} total | {self.params.with_reflection} reflect",
            "",
        ]
        
        # Vulnerability hints
        hints = []
        if self.vuln_hints.admin_panel: hints.append("admin_panel")
        if self.vuln_hints.git_exposed: hints.append("git_exposed")
        if self.vuln_hints.debug_mode: hints.append("debug_mode")
        if self.vuln_hints.cors_misconfigured: hints.append("cors")
        if self.vuln_hints.sqli_likely: hints.append("sqli")
        if self.vuln_hints.xss_likely: hints.append("xss")
        
        if hints:
            lines.append(f"Hints: {', '.join(hints)}")
        
        if self.tags:
            lines.append(f"Tags: {', '.join(self.tags)}")
            
        return "\n".join(lines)


class StateManager:
    """
    Manages state persistence and retrieval.
    State is saved as JSON for each target.
    """
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.states_dir = self.output_dir / "states"
        self.states_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, TargetState] = {}
    
    def _state_path(self, domain: str) -> Path:
        """Get the state file path for a domain"""
        safe_name = domain.replace(".", "_").replace("/", "_")
        return self.states_dir / f"{safe_name}.json"
    
    def create(self, domain: str, base_path: str) -> TargetState:
        """Create a new target state"""
        state = TargetState(domain=domain, base_path=base_path)
        self.save(state)
        return state
    
    def load(self, domain: str) -> Optional[TargetState]:
        """Load state from disk"""
        # Check cache first
        if domain in self._cache:
            return self._cache[domain]
        
        path = self._state_path(domain)
        if not path.exists():
            return None
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            state = TargetState.from_dict(data)
            self._cache[domain] = state
            return state
        except Exception as e:
            print(f"Error loading state for {domain}: {e}")
            return None
    
    def save(self, state: TargetState):
        """Save state to disk"""
        state.update_timestamp()
        path = self._state_path(state.domain)
        
        with open(path, 'w') as f:
            json.dump(state.to_dict(), f, indent=2)
        
        self._cache[state.domain] = state
    
    def get_or_create(self, domain: str, base_path: str) -> TargetState:
        """Load existing state or create new one"""
        state = self.load(domain)
        if state is None:
            state = self.create(domain, base_path)
        return state
    
    def list_all(self) -> List[TargetState]:
        """List all saved states"""
        states = []
        for path in self.states_dir.glob("*.json"):
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
                states.append(TargetState.from_dict(data))
            except Exception:
                continue
        return states
    
    def get_by_priority(self, min_score: int = 0) -> List[TargetState]:
        """Get states sorted by score"""
        states = self.list_all()
        return sorted(
            [s for s in states if s.score >= min_score],
            key=lambda s: s.score,
            reverse=True
        )
    
    def export_summary(self, output_path: Optional[str] = None) -> str:
        """Export summary of all states"""
        states = self.get_by_priority()
        
        lines = [
            "═══════════════════════════════════════════════════════════",
            "              SHADOW v6 - Target Intelligence              ",
            "═══════════════════════════════════════════════════════════",
            f"Total Targets: {len(states)}",
            f"Generated: {datetime.now().isoformat()}",
            "",
        ]
        
        # Group by priority
        for priority in ['critical', 'high', 'medium', 'low']:
            priority_states = [s for s in states if s.priority == priority]
            if priority_states:
                lines.append(f"\n{'═' * 20} {priority.upper()} PRIORITY {'═' * 20}")
                for state in priority_states:
                    lines.append("")
                    lines.append(state.summary())
        
        summary = "\n".join(lines)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(summary)
        
        return summary

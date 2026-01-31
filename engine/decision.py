"""
SHADOW v6 - Decision Engine

The brain of SHADOW. Makes decisions about what to run and when.
No scanner runs without a reason. Automation stops when human reasoning is better.
"""

import subprocess
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, Tuple
from enum import Enum
from pathlib import Path

from .state import TargetState, TargetPhase, WAFType, StateManager
from .scorer import Scorer, Score


class DecisionType(Enum):
    """Types of decisions the engine can make"""
    RUN_MODULE = "run_module"      # Execute a module
    SKIP_MODULE = "skip_module"    # Skip a module with reason
    RUN_TOOL = "run_tool"          # Execute a specific tool
    PAUSE = "pause"                # Pause for rate limiting
    STOP = "stop"                  # Stop scanning this target
    MANUAL = "manual"              # Requires human decision
    PRIORITIZE = "prioritize"      # Change target priority


@dataclass
class Decision:
    """A decision made by the engine"""
    type: DecisionType
    action: str  # What to do
    reason: str  # Why
    confidence: float = 1.0  # 0-1, how confident we are
    data: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self):
        return f"[{self.type.value}] {self.action}: {self.reason}"


@dataclass
class ModuleCondition:
    """Conditions for running a module"""
    name: str
    required_state: Dict[str, Any]  # State conditions that must be true
    recommended_score: int = 0      # Minimum score to run
    tools: List[str] = field(default_factory=list)  # Tools this module uses
    produces: List[str] = field(default_factory=list)  # State fields it updates


class DecisionEngine:
    """
    The Decision Engine evaluates target state and decides:
    1. Which modules to run
    2. Which tools to use
    3. When to stop automation and recommend manual testing
    
    Core Principle: No scanner without reason.
    """
    
    def __init__(self, state_manager: StateManager, script_dir: str):
        self.state_manager = state_manager
        self.script_dir = Path(script_dir)
        self.scorer = Scorer()
        
        # Define module conditions
        self._setup_module_rules()
        
        # Tool conditions - when to use each tool
        self._setup_tool_rules()
    
    def _setup_module_rules(self):
        """Define when each module should run"""
        self.module_rules: Dict[str, ModuleCondition] = {
            # Intel - always runs first
            "01_intel": ModuleCondition(
                name="Intelligence Gathering",
                required_state={},  # No prerequisites
                tools=["whois", "dig", "host"],
                produces=["fingerprint", "dns_info"]
            ),
            
            # Subdomains - always runs
            "02_subdomains": ModuleCondition(
                name="Subdomain Discovery",
                required_state={},
                tools=["subfinder", "amass"],
                produces=["subdomains_count"]
            ),
            
            # DNS - needs subdomains
            "03_dns": ModuleCondition(
                name="DNS Resolution",
                required_state={"subdomains_count": lambda x: x > 0},
                tools=["dnsx", "massdns"],
                produces=["alive_hosts"]
            ),
            
            # HTTP Probing - needs resolved hosts
            "05_http": ModuleCondition(
                name="HTTP Probing",
                required_state={"alive_hosts": lambda x: len(x) > 0},
                tools=["httpx"],
                produces=["fingerprint", "waf"]
            ),
            
            # Content Discovery - only if no heavy WAF
            "06_content": ModuleCondition(
                name="Content Discovery",
                required_state={
                    "waf": lambda x: x not in [WAFType.AKAMAI, WAFType.IMPERVA],
                    "alive_hosts": lambda x: len(x) > 0
                },
                recommended_score=3,
                tools=["ffuf", "feroxbuster"],
                produces=["vuln_hints.backup_files", "vuln_hints.admin_panel"]
            ),
            
            # JS Analysis - only if JS detected
            "07_js": ModuleCondition(
                name="JavaScript Analysis",
                required_state={"js.has_js": True},
                recommended_score=4,
                tools=["katana", "linkfinder"],
                produces=["js.endpoints_found", "js.secrets_found"]
            ),
            
            # Params - needs JS or content discovery
            "08_params": ModuleCondition(
                name="Parameter Discovery",
                required_state={"alive_hosts": lambda x: len(x) > 0},
                tools=["katana"],
                produces=["params"]
            ),
            
            # Vuln scanning - conditional based on findings
            "09_vuln": ModuleCondition(
                name="Vulnerability Scanning",
                required_state={"score": lambda x: x >= 4},  # Only if interesting
                recommended_score=5,
                tools=["nuclei"],
                produces=["vulns"]
            ),
        }
    
    def _setup_tool_rules(self):
        """Define when each scanning tool should be used"""
        self.tool_rules = {
            # XSS tools
            "dalfox": {
                "conditions": [
                    ("params.xss_candidates", lambda x: len(x) > 0),
                    ("params.with_reflection", lambda x: x > 0),
                ],
                "reason": "Parameters reflect input - XSS testing warranted"
            },
            "kxss": {
                "conditions": [
                    ("params.with_reflection", lambda x: x > 3),
                ],
                "reason": "Multiple reflection points found"
            },
            
            # SQLi tools
            "sqlmap": {
                "conditions": [
                    ("params.sqli_candidates", lambda x: len(x) > 0),
                    ("vuln_hints.error_messages", True),
                ],
                "reason": "SQL error messages or SQL-like parameters detected",
                "manual_recommended": True
            },
            "ghauri": {
                "conditions": [
                    ("params.sqli_candidates", lambda x: len(x) > 0),
                ],
                "reason": "SQLi candidates require testing"
            },
            
            # SSRF tools
            "ssrf_test": {
                "conditions": [
                    ("params.ssrf_candidates", lambda x: len(x) > 0),
                ],
                "reason": "URL parameters detected"
            },
            
            # CORS
            "corsy": {
                "conditions": [
                    ("vuln_hints.cors_misconfigured", True),
                    ("api.detected", True),
                ],
                "reason": "CORS headers or API detected"
            },
            
            # GraphQL
            "graphql_introspection": {
                "conditions": [
                    ("api.type", lambda x: x == "graphql"),
                ],
                "reason": "GraphQL API detected"
            },
            
            # Nuclei - always with reason
            "nuclei": {
                "conditions": [
                    ("alive_hosts", lambda x: len(x) > 0),
                ],
                "reason": "Active hosts require vulnerability scanning",
                "severity_based": True  # Adjust templates based on score
            },
            
            # 403 Bypass
            "byp4xx": {
                "conditions": [
                    ("vuln_hints.admin_panel", True),
                ],
                "reason": "Admin panel or restricted paths found"
            },
            
            # Takeover
            "subjack": {
                "conditions": [
                    ("subdomains_count", lambda x: x > 10),
                ],
                "reason": "Multiple subdomains = takeover potential"
            },
        }
    
    def _check_condition(self, state: TargetState, path: str, condition: Any) -> bool:
        """Check a single condition against state"""
        # Navigate nested path like "js.has_js"
        value = state
        for part in path.split("."):
            if hasattr(value, part):
                value = getattr(value, part)
            elif isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return False
        
        # Evaluate condition
        if callable(condition):
            return condition(value)
        else:
            return value == condition
    
    def should_run_module(self, state: TargetState, module: str) -> Decision:
        """Decide if a module should run"""
        if module not in self.module_rules:
            return Decision(
                type=DecisionType.RUN_MODULE,
                action=module,
                reason="No specific rules - running with defaults"
            )
        
        rule = self.module_rules[module]
        
        # Check required state conditions
        for path, condition in rule.required_state.items():
            if not self._check_condition(state, path, condition):
                return Decision(
                    type=DecisionType.SKIP_MODULE,
                    action=module,
                    reason=f"Condition not met: {path}",
                    data={"condition": path}
                )
        
        # Check score threshold
        if rule.recommended_score > 0 and state.score < rule.recommended_score:
            return Decision(
                type=DecisionType.SKIP_MODULE,
                action=module,
                reason=f"Score {state.score} < required {rule.recommended_score}",
                confidence=0.7,
                data={"score": state.score, "required": rule.recommended_score}
            )
        
        return Decision(
            type=DecisionType.RUN_MODULE,
            action=module,
            reason=f"All conditions met for {rule.name}",
            data={"tools": rule.tools}
        )
    
    def should_run_tool(self, state: TargetState, tool: str) -> Decision:
        """Decide if a specific tool should run"""
        if tool not in self.tool_rules:
            return Decision(
                type=DecisionType.SKIP_MODULE,
                action=tool,
                reason="No rules defined - skipping to avoid noise"
            )
        
        rule = self.tool_rules[tool]
        conditions_met = []
        
        for path, condition in rule["conditions"]:
            if self._check_condition(state, path, condition):
                conditions_met.append(path)
        
        if not conditions_met:
            return Decision(
                type=DecisionType.SKIP_MODULE,
                action=tool,
                reason="No conditions met - tool would add noise without value"
            )
        
        # Check if manual is recommended
        if rule.get("manual_recommended"):
            return Decision(
                type=DecisionType.MANUAL,
                action=tool,
                reason=f"{rule['reason']} - MANUAL TESTING RECOMMENDED",
                data={"conditions_met": conditions_met}
            )
        
        return Decision(
            type=DecisionType.RUN_TOOL,
            action=tool,
            reason=rule["reason"],
            data={"conditions_met": conditions_met}
        )
    
    def get_next_actions(self, state: TargetState) -> List[Decision]:
        """Get all recommended next actions for a target"""
        decisions = []
        
        # Determine current phase and what should happen next
        if state.phase == TargetPhase.INIT:
            decisions.append(Decision(
                type=DecisionType.RUN_MODULE,
                action="01_intel",
                reason="Starting intelligence gathering"
            ))
            decisions.append(Decision(
                type=DecisionType.RUN_MODULE,
                action="02_subdomains",
                reason="Starting subdomain enumeration"
            ))
        
        elif state.phase == TargetPhase.RECON:
            # Check what modules should run next
            for module in ["03_dns", "05_http"]:
                decision = self.should_run_module(state, module)
                decisions.append(decision)
        
        elif state.phase == TargetPhase.ENUMERATION:
            for module in ["06_content", "07_js", "08_params"]:
                decision = self.should_run_module(state, module)
                decisions.append(decision)
        
        elif state.phase == TargetPhase.ANALYSIS:
            # Decide which tools to run based on findings
            for tool in self.tool_rules.keys():
                decision = self.should_run_tool(state, tool)
                if decision.type in [DecisionType.RUN_TOOL, DecisionType.MANUAL]:
                    decisions.append(decision)
        
        # Check if we should stop and go manual
        if state.score >= 10:
            decisions.append(Decision(
                type=DecisionType.MANUAL,
                action="manual_review",
                reason=f"High score ({state.score}) - human analysis more valuable than automation"
            ))
        
        # Check for blocking
        if state.blocked:
            decisions.append(Decision(
                type=DecisionType.STOP,
                action="stop_scanning",
                reason="Target is blocking our requests"
            ))
        
        return decisions
    
    def execute_module(self, state: TargetState, module: str) -> Tuple[bool, str]:
        """Execute a Bash module and update state"""
        decision = self.should_run_module(state, module)
        
        if decision.type == DecisionType.SKIP_MODULE:
            state.mark_module_skipped(module, decision.reason)
            return False, decision.reason
        
        # Build the command
        module_path = self.script_dir / "modules" / f"{module}.sh"
        if not module_path.exists():
            return False, f"Module not found: {module_path}"
        
        # Export state as environment variables for Bash
        env = os.environ.copy()
        env["SHADOW_TARGET"] = state.domain
        env["SHADOW_BASE"] = state.base_path
        env["SHADOW_SCORE"] = str(state.score)
        env["SHADOW_WAF"] = state.waf.value
        env["SHADOW_PHASE"] = state.phase.value
        
        # Stealth mode if WAF detected
        if state.waf != WAFType.NONE:
            env["STEALTH_MODE"] = "true"
        
        try:
            # Source utils and run module
            cmd = f"""
            source "{self.script_dir}/utils/log.sh"
            source "{self.script_dir}/utils/check.sh"
            source "{self.script_dir}/utils/noise.sh"
            source "{module_path}"
            run "{state.domain}" "{state.base_path}"
            """
            
            result = subprocess.run(
                ["bash", "-c", cmd],
                env=env,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            state.mark_module_executed(module)
            
            # Update state based on module output
            self._update_state_from_files(state)
            
            # Recalculate score
            self.scorer.update_state_score(state)
            
            # Save state
            self.state_manager.save(state)
            
            return True, f"Module {module} completed"
            
        except subprocess.TimeoutExpired:
            return False, "Module timed out"
        except Exception as e:
            return False, str(e)
    
    def _update_state_from_files(self, state: TargetState):
        """Update state by reading output files from modules"""
        base = Path(state.base_path)
        
        # Subdomains
        subs_file = base / "subs" / "alive.txt"
        if subs_file.exists():
            with open(subs_file) as f:
                subs = [l.strip() for l in f if l.strip()]
                state.subdomains_count = len(subs)
        
        # Alive hosts
        alive_file = base / "http" / "alive.txt"
        if alive_file.exists():
            with open(alive_file) as f:
                state.alive_hosts = [l.strip() for l in f if l.strip()]
        
        # Tech detection
        tech_file = base / "http" / "tech.txt"
        if tech_file.exists():
            with open(tech_file) as f:
                for line in f:
                    if "[" in line and "]" in line:
                        tech = line.split("[")[1].split("]")[0]
                        if tech not in state.fingerprint.technologies:
                            state.fingerprint.technologies.append(tech)
        
        # JS endpoints
        js_endpoints = base / "js" / "endpoints.txt"
        if js_endpoints.exists():
            state.js.has_js = True
            with open(js_endpoints) as f:
                state.js.endpoints_found = sum(1 for _ in f)
        
        # JS secrets
        js_secrets = base / "js" / "secrets.txt"
        if js_secrets.exists():
            with open(js_secrets) as f:
                state.js.secrets_found = sum(1 for _ in f)
        
        # Params
        params_file = base / "params" / "all_urls.txt"
        if params_file.exists():
            with open(params_file) as f:
                state.params.total_count = sum(1 for l in f if "?" in l)
        
        # GF patterns
        for vuln_type, attr in [("xss", "xss_candidates"), ("sqli", "sqli_candidates"), 
                                 ("ssrf", "ssrf_candidates"), ("idor", "idor_candidates")]:
            gf_file = base / "params" / f"gf_{vuln_type}.txt"
            if gf_file.exists():
                with open(gf_file) as f:
                    setattr(state.params, attr, [l.strip() for l in f if l.strip()][:50])
        
        # Vuln hints from content discovery
        content_dir = base / "content"
        if content_dir.exists():
            all_content = content_dir / "all_ffuf.txt"
            if all_content.exists():
                with open(all_content) as f:
                    content = f.read().lower()
                    if "admin" in content:
                        state.vuln_hints.admin_panel = True
                    if ".git" in content:
                        state.vuln_hints.git_exposed = True
                    if ".env" in content:
                        state.vuln_hints.env_exposed = True
                    if "backup" in content or ".bak" in content:
                        state.vuln_hints.backup_files = True
    
    def run_pipeline(self, domain: str, base_path: str) -> TargetState:
        """Run the complete decision-driven pipeline"""
        state = self.state_manager.get_or_create(domain, base_path)
        
        # Phase 1: Initial Recon
        state.phase = TargetPhase.RECON
        for module in ["01_intel", "02_subdomains", "03_dns"]:
            self.execute_module(state, module)
        
        # Calculate initial score
        self.scorer.update_state_score(state)
        self.state_manager.save(state)
        
        # Phase 2: Enumeration
        state.phase = TargetPhase.ENUMERATION
        for module in ["05_http", "06_content", "07_js", "08_params"]:
            decision = self.should_run_module(state, module)
            if decision.type == DecisionType.RUN_MODULE:
                self.execute_module(state, module)
                # Recalculate after each module
                self.scorer.update_state_score(state)
        
        self.state_manager.save(state)
        
        # Phase 3: Analysis - decide what vuln scanning to do
        state.phase = TargetPhase.ANALYSIS
        
        decisions = self.get_next_actions(state)
        
        # If score is high enough, recommend manual
        if state.score >= 10:
            state.add_note("HIGH VALUE TARGET - Manual analysis recommended")
            state.phase = TargetPhase.COMPLETE
        else:
            # Run automated vuln scanning
            for decision in decisions:
                if decision.type == DecisionType.RUN_TOOL:
                    state.add_note(f"Auto: {decision.action} - {decision.reason}")
            
            self.execute_module(state, "09_vuln")
            state.phase = TargetPhase.VULNERABILITY
        
        self.state_manager.save(state)
        return state

"""
SHADOW v6 - Scoring System

Real scoring based on attack surface, not random numbers.
Every score has a reason. Every reason is actionable.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from enum import Enum

from .state import TargetState, WAFType


class ScoreCategory(Enum):
    """Categories of scoring factors"""
    AUTH = "auth"           # Authentication surface
    API = "api"             # API surface
    PARAMS = "params"       # Parameter surface
    JS = "js"               # JavaScript intelligence
    VULNS = "vulns"         # Vulnerability hints
    TECH = "tech"           # Technology stack
    WAF = "waf"             # WAF presence (negative)
    EXPOSURE = "exposure"   # Exposed sensitive data


@dataclass
class ScoreFactor:
    """A single scoring factor"""
    category: ScoreCategory
    name: str
    points: int
    reason: str
    actionable: str  # What to do about this


@dataclass
class Score:
    """Complete score breakdown for a target"""
    total: int = 0
    factors: List[ScoreFactor] = field(default_factory=list)
    priority: str = "low"
    recommendation: str = ""
    attack_paths: List[str] = field(default_factory=list)
    
    def add_factor(self, factor: ScoreFactor):
        """Add a scoring factor"""
        self.factors.append(factor)
        self.total += factor.points
    
    def calculate_priority(self):
        """Calculate priority based on total score"""
        if self.total >= 15:
            self.priority = "critical"
        elif self.total >= 10:
            self.priority = "high"
        elif self.total >= 5:
            self.priority = "medium"
        else:
            self.priority = "low"
    
    def summary(self) -> str:
        """Human-readable score summary"""
        lines = [
            f"Score: {self.total} ({self.priority.upper()})",
            "",
            "Factors:"
        ]
        
        # Group by category
        categories = {}
        for factor in self.factors:
            cat = factor.category.value
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(factor)
        
        for cat, factors in categories.items():
            cat_total = sum(f.points for f in factors)
            sign = "+" if cat_total >= 0 else ""
            lines.append(f"  [{cat.upper()}] {sign}{cat_total}")
            for f in factors:
                sign = "+" if f.points >= 0 else ""
                lines.append(f"    {sign}{f.points}: {f.name}")
                lines.append(f"         → {f.reason}")
        
        if self.attack_paths:
            lines.append("")
            lines.append("Suggested Attack Paths:")
            for i, path in enumerate(self.attack_paths, 1):
                lines.append(f"  {i}. {path}")
        
        if self.recommendation:
            lines.append("")
            lines.append(f"Recommendation: {self.recommendation}")
        
        return "\n".join(lines)


class Scorer:
    """
    Calculates target score based on state.
    
    Scoring Philosophy:
    - Every point must be justified
    - Negative scores for obstacles
    - Attack paths are suggested based on factors
    """
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SCORING RULES
    # ═══════════════════════════════════════════════════════════════════════════
    
    # Authentication surface
    AUTH_RULES = {
        "has_login": (3, "Login functionality = potential auth bypass, brute force, credential stuffing"),
        "has_oauth": (4, "OAuth = token theft, redirect manipulation, scope escalation"),
        "has_sso": (3, "SSO = SAML attacks, assertion manipulation"),
        "has_jwt": (5, "JWT = algorithm confusion, secret bruteforce, claim tampering"),
        "has_api_keys": (4, "API keys in JS = potential key leakage"),
    }
    
    # API surface
    API_RULES = {
        "graphql": (6, "GraphQL = introspection, nested queries, batching attacks"),
        "rest_with_swagger": (4, "Swagger exposed = full API documentation"),
        "grpc": (3, "gRPC = proto file extraction, reflection"),
        "soap": (2, "SOAP = XXE, injection in XML"),
    }
    
    # Technology bonuses
    TECH_BONUSES = {
        "wordpress": (3, "WordPress = plugin vulns, xmlrpc, wp-json"),
        "drupal": (4, "Drupal = Drupalgeddon variants"),
        "joomla": (3, "Joomla = known CVEs"),
        "jenkins": (5, "Jenkins = Groovy RCE, credential access"),
        "gitlab": (4, "GitLab = repo access, CI/CD secrets"),
        "confluence": (4, "Confluence = CVE-2022-26134 and variants"),
        "jira": (3, "Jira = SSRF, user enumeration"),
        "elasticsearch": (5, "Elasticsearch = open cluster, data access"),
        "kibana": (4, "Kibana = RCE vulnerabilities"),
        "grafana": (4, "Grafana = path traversal, auth bypass"),
        "spring": (4, "Spring = Spring4Shell, actuator endpoints"),
        "struts": (5, "Struts = OGNL injection RCE"),
    }
    
    # WAF penalties
    WAF_PENALTIES = {
        WAFType.CLOUDFLARE: -3,
        WAFType.AKAMAI: -4,
        WAFType.AWS_WAF: -2,
        WAFType.IMPERVA: -4,
        WAFType.F5: -3,
        WAFType.MODSECURITY: -2,
        WAFType.SUCURI: -2,
        WAFType.UNKNOWN: -1,
        WAFType.NONE: 0,
    }
    
    def calculate(self, state: TargetState) -> Score:
        """Calculate complete score for a target state"""
        score = Score()
        
        # ─────────────────────────────────────────────────────────────────────
        # Authentication Surface
        # ─────────────────────────────────────────────────────────────────────
        if state.auth.has_login:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.AUTH,
                name="Login Form Detected",
                points=3,
                reason="Login functionality enables auth testing",
                actionable="Test for auth bypass, brute force, credential stuffing"
            ))
        
        if state.auth.has_oauth:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.AUTH,
                name="OAuth Implementation",
                points=4,
                reason="OAuth flows are complex and often misconfigured",
                actionable="Test redirect_uri manipulation, token theft, scope escalation"
            ))
        
        if state.auth.has_jwt:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.AUTH,
                name="JWT Authentication",
                points=5,
                reason="JWT is frequently implemented incorrectly",
                actionable="Test alg:none, HS256/RS256 confusion, weak secrets"
            ))
            score.attack_paths.append("JWT → Algorithm confusion → Token forgery")
        
        if state.auth.has_sso:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.AUTH,
                name="SSO Integration",
                points=3,
                reason="SAML/SSO has complex trust relationships",
                actionable="Test SAML assertion manipulation, signature bypass"
            ))
        
        # Auth + Params combo
        if state.auth.has_login and state.params.total_count > 20:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.AUTH,
                name="Auth + Rich Params",
                points=5,
                reason="Authentication with many parameters = IDOR/privilege escalation potential",
                actionable="Focus on ID parameters after authentication"
            ))
            score.attack_paths.append("Auth → Enumerate IDs → IDOR")
        
        # ─────────────────────────────────────────────────────────────────────
        # API Surface  
        # ─────────────────────────────────────────────────────────────────────
        if state.api.detected:
            if state.api.type == "graphql":
                score.add_factor(ScoreFactor(
                    category=ScoreCategory.API,
                    name="GraphQL API",
                    points=6,
                    reason="GraphQL introspection often enabled, complex query attacks",
                    actionable="Run introspection, test batching, nested queries, DoS"
                ))
                score.attack_paths.append("GraphQL → Introspection → Hidden mutations → Data access")
                
                if state.api.has_graphql_introspection:
                    score.add_factor(ScoreFactor(
                        category=ScoreCategory.API,
                        name="GraphQL Introspection Enabled",
                        points=3,
                        reason="Full schema is exposed",
                        actionable="Extract schema, find hidden queries/mutations"
                    ))
            
            if state.api.has_swagger:
                score.add_factor(ScoreFactor(
                    category=ScoreCategory.API,
                    name="Swagger/OpenAPI Exposed",
                    points=4,
                    reason="Complete API documentation is accessible",
                    actionable="Import to Burp, test all endpoints systematically"
                ))
                score.attack_paths.append("Swagger → Import to Burp → Test admin endpoints")
            
            # Many API endpoints
            if state.api.endpoints_count > 50:
                score.add_factor(ScoreFactor(
                    category=ScoreCategory.API,
                    name=f"Large API Surface ({state.api.endpoints_count} endpoints)",
                    points=3,
                    reason="Large API = more attack surface",
                    actionable="Focus on admin, user, and file endpoints"
                ))
        
        # ─────────────────────────────────────────────────────────────────────
        # JavaScript Intelligence
        # ─────────────────────────────────────────────────────────────────────
        if state.js.has_js:
            if state.js.secrets_found > 0:
                score.add_factor(ScoreFactor(
                    category=ScoreCategory.JS,
                    name=f"Secrets in JS ({state.js.secrets_found})",
                    points=min(state.js.secrets_found * 2, 8),
                    reason="Hardcoded secrets in JavaScript files",
                    actionable="Extract and validate each secret"
                ))
                score.attack_paths.append("JS Analysis → Extract secrets → Validate access")
            
            if state.js.api_keys_found > 0:
                score.add_factor(ScoreFactor(
                    category=ScoreCategory.JS,
                    name=f"API Keys in JS ({state.js.api_keys_found})",
                    points=min(state.js.api_keys_found * 3, 9),
                    reason="API keys exposed in client-side code",
                    actionable="Test each key for access level and scope"
                ))
            
            if state.js.source_maps:
                score.add_factor(ScoreFactor(
                    category=ScoreCategory.JS,
                    name="Source Maps Available",
                    points=4,
                    reason="Original source code can be reconstructed",
                    actionable="Download .map files, reconstruct source, analyze"
                ))
            
            if state.js.endpoints_found > 30:
                score.add_factor(ScoreFactor(
                    category=ScoreCategory.JS,
                    name=f"Hidden Endpoints in JS ({state.js.endpoints_found})",
                    points=3,
                    reason="Many undocumented endpoints found in JS",
                    actionable="Test each endpoint for auth bypass"
                ))
        
        # ─────────────────────────────────────────────────────────────────────
        # Vulnerability Hints
        # ─────────────────────────────────────────────────────────────────────
        if state.vuln_hints.admin_panel:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.VULNS,
                name="Admin Panel Detected",
                points=8,
                reason="Admin access = high impact",
                actionable="Test default creds, auth bypass, functionality abuse"
            ))
            score.attack_paths.append("Admin Panel → Auth bypass → Full control")
        
        if state.vuln_hints.git_exposed:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.EXPOSURE,
                name=".git Exposed",
                points=7,
                reason="Full source code and history accessible",
                actionable="Use git-dumper, extract secrets from history"
            ))
            score.attack_paths.append(".git → Extract repo → Find secrets in history")
        
        if state.vuln_hints.env_exposed:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.EXPOSURE,
                name=".env File Exposed",
                points=8,
                reason="Environment variables often contain credentials",
                actionable="Download and extract all credentials"
            ))
        
        if state.vuln_hints.debug_mode:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.VULNS,
                name="Debug Mode Enabled",
                points=5,
                reason="Debug = stack traces, internal info, potential RCE",
                actionable="Look for debug endpoints, verbose errors"
            ))
        
        if state.vuln_hints.cors_misconfigured:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.VULNS,
                name="CORS Misconfiguration",
                points=4,
                reason="Cross-origin attacks possible",
                actionable="Test for credential theft via CORS"
            ))
        
        if state.vuln_hints.backup_files:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.EXPOSURE,
                name="Backup Files Found",
                points=5,
                reason="Backup files may contain source code or data",
                actionable="Download and analyze each backup file"
            ))
        
        if state.vuln_hints.error_messages:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.VULNS,
                name="Verbose Error Messages",
                points=2,
                reason="Errors leak internal information",
                actionable="Use errors to map internal structure"
            ))
        
        if state.vuln_hints.stack_traces:
            score.add_factor(ScoreFactor(
                category=ScoreCategory.VULNS,
                name="Stack Traces Exposed",
                points=3,
                reason="Stack traces reveal framework, paths, versions",
                actionable="Extract version info, find known CVEs"
            ))
        
        # Injection candidates
        if state.params.sqli_candidates:
            count = len(state.params.sqli_candidates)
            score.add_factor(ScoreFactor(
                category=ScoreCategory.PARAMS,
                name=f"SQLi Candidates ({count})",
                points=min(count, 5),
                reason="Parameters show SQL-like behavior",
                actionable="Manual SQLi testing on each candidate"
            ))
            score.attack_paths.append("SQLi candidates → Manual testing → Data extraction")
        
        if state.params.xss_candidates:
            count = len(state.params.xss_candidates)
            score.add_factor(ScoreFactor(
                category=ScoreCategory.PARAMS,
                name=f"XSS Candidates ({count})",
                points=min(count, 4),
                reason="Parameters reflect input",
                actionable="Test each for context-specific XSS"
            ))
        
        if state.params.ssrf_candidates:
            count = len(state.params.ssrf_candidates)
            score.add_factor(ScoreFactor(
                category=ScoreCategory.PARAMS,
                name=f"SSRF Candidates ({count})",
                points=min(count * 2, 6),
                reason="Parameters accept URLs",
                actionable="Test internal network access, cloud metadata"
            ))
            score.attack_paths.append("SSRF candidate → Cloud metadata → Credentials")
        
        if state.params.idor_candidates:
            count = len(state.params.idor_candidates)
            score.add_factor(ScoreFactor(
                category=ScoreCategory.PARAMS,
                name=f"IDOR Candidates ({count})",
                points=min(count * 2, 6),
                reason="ID-like parameters found",
                actionable="Enumerate IDs, test for unauthorized access"
            ))
        
        # ─────────────────────────────────────────────────────────────────────
        # Technology Stack
        # ─────────────────────────────────────────────────────────────────────
        for tech in state.fingerprint.technologies:
            tech_lower = tech.lower()
            for tech_name, (points, reason) in self.TECH_BONUSES.items():
                if tech_name in tech_lower:
                    score.add_factor(ScoreFactor(
                        category=ScoreCategory.TECH,
                        name=f"{tech} Detected",
                        points=points,
                        reason=reason,
                        actionable=f"Research latest {tech} CVEs"
                    ))
                    break
        
        # ─────────────────────────────────────────────────────────────────────
        # WAF Penalties
        # ─────────────────────────────────────────────────────────────────────
        if state.waf != WAFType.NONE:
            penalty = self.WAF_PENALTIES.get(state.waf, -1)
            score.add_factor(ScoreFactor(
                category=ScoreCategory.WAF,
                name=f"{state.waf.value} WAF",
                points=penalty,
                reason="WAF will block automated attacks",
                actionable="Use WAF bypass techniques, slower scanning"
            ))
        
        # ─────────────────────────────────────────────────────────────────────
        # Calculate Final Priority
        # ─────────────────────────────────────────────────────────────────────
        score.calculate_priority()
        
        # Generate recommendation
        if score.priority == "critical":
            score.recommendation = "MANUAL FOCUS REQUIRED. Drop everything and investigate."
        elif score.priority == "high":
            score.recommendation = "High potential. Allocate dedicated time for manual testing."
        elif score.priority == "medium":
            score.recommendation = "Worth investigating after high-priority targets."
        else:
            score.recommendation = "Low priority. Quick automated scan only."
        
        return score
    
    def update_state_score(self, state: TargetState) -> Score:
        """Calculate score and update state"""
        score = self.calculate(state)
        state.score = score.total
        state.priority = score.priority
        return score

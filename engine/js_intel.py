"""
SHADOW v6 - JavaScript Intelligence Engine

Not just extracting URLs from JS. Understanding:
- Authentication flows
- API relationships  
- Privilege boundaries
- Data flows
"""

import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path
from enum import Enum


class FlowType(Enum):
    """Types of discovered flows"""
    AUTH = "auth"               # Authentication flow
    API_CALL = "api_call"       # API interaction
    DATA_FETCH = "data_fetch"   # Data retrieval
    DATA_SUBMIT = "data_submit" # Data submission
    REDIRECT = "redirect"       # Navigation/redirect
    PRIVILEGE = "privilege"     # Privilege change
    FILE_OP = "file_op"         # File operations
    ADMIN = "admin"             # Admin functionality


class SensitivityLevel(Enum):
    """Sensitivity of discovered items"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Endpoint:
    """A discovered endpoint"""
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    source_file: str = ""
    context: str = ""  # Code context where it was found


@dataclass
class Secret:
    """A discovered secret"""
    type: str  # api_key, token, password, etc.
    value: str
    source_file: str
    line: int = 0
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM
    context: str = ""
    
    def masked_value(self) -> str:
        """Return masked version for safe display"""
        if len(self.value) <= 8:
            return "*" * len(self.value)
        return self.value[:4] + "*" * (len(self.value) - 8) + self.value[-4:]


@dataclass
class Flow:
    """A discovered application flow"""
    type: FlowType
    name: str
    steps: List[str]
    endpoints: List[Endpoint] = field(default_factory=list)
    requires_auth: bool = False
    privilege_level: str = "user"  # user, admin, etc.
    description: str = ""
    attack_potential: str = ""


@dataclass
class JSAnalysis:
    """Complete JS analysis results"""
    endpoints: List[Endpoint] = field(default_factory=list)
    secrets: List[Secret] = field(default_factory=list)
    flows: List[Flow] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    frameworks: List[str] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    
    def high_value_count(self) -> int:
        """Count high-value findings"""
        count = 0
        count += len([s for s in self.secrets if s.sensitivity.value >= 3])
        count += len([f for f in self.flows if f.type in [FlowType.AUTH, FlowType.ADMIN, FlowType.PRIVILEGE]])
        count += len([e for e in self.endpoints if e.auth_required])
        return count


class JSIntelligence:
    """
    JavaScript Intelligence Engine
    
    Analyzes JavaScript files to understand:
    - Application structure
    - Authentication mechanisms
    - API endpoints and their relationships
    - Sensitive data flows
    """
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DETECTION PATTERNS
    # ═══════════════════════════════════════════════════════════════════════════
    
    # API endpoint patterns
    ENDPOINT_PATTERNS = [
        # Fetch/axios calls
        r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'axios\s*\(\s*\{[^}]*url:\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # jQuery AJAX
        r'\$\.(ajax|get|post)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'\$\.(ajax|get|post)\s*\(\s*\{[^}]*url:\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # Angular HTTP
        r'http\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'HttpClient\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # Generic URL assignments
        r'(api|endpoint|url|path|route)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
        r'baseURL\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
    ]
    
    # Secret patterns with sensitivity
    SECRET_PATTERNS = [
        # API Keys (HIGH)
        (r'[\'"`](sk_live_[a-zA-Z0-9]{24,})[\'"`]', "stripe_secret_key", SensitivityLevel.CRITICAL),
        (r'[\'"`](sk_test_[a-zA-Z0-9]{24,})[\'"`]', "stripe_test_key", SensitivityLevel.HIGH),
        (r'[\'"`](pk_live_[a-zA-Z0-9]{24,})[\'"`]', "stripe_public_key", SensitivityLevel.MEDIUM),
        (r'[\'"`](AKIA[A-Z0-9]{16})[\'"`]', "aws_access_key", SensitivityLevel.CRITICAL),
        (r'[\'"`]([a-zA-Z0-9/+]{40})[\'"`]', "aws_secret_key", SensitivityLevel.CRITICAL),
        (r'[\'"`](ghp_[a-zA-Z0-9]{36})[\'"`]', "github_token", SensitivityLevel.CRITICAL),
        (r'[\'"`](gho_[a-zA-Z0-9]{36})[\'"`]', "github_oauth", SensitivityLevel.CRITICAL),
        (r'[\'"`](xox[baprs]-[a-zA-Z0-9-]+)[\'"`]', "slack_token", SensitivityLevel.CRITICAL),
        
        # Generic API keys
        (r'api[_-]?key\s*[:=]\s*[\'"`]([^\'"`]{16,})[\'"`]', "api_key", SensitivityLevel.HIGH),
        (r'api[_-]?secret\s*[:=]\s*[\'"`]([^\'"`]{16,})[\'"`]', "api_secret", SensitivityLevel.HIGH),
        (r'auth[_-]?token\s*[:=]\s*[\'"`]([^\'"`]{16,})[\'"`]', "auth_token", SensitivityLevel.HIGH),
        (r'access[_-]?token\s*[:=]\s*[\'"`]([^\'"`]{16,})[\'"`]', "access_token", SensitivityLevel.HIGH),
        
        # Passwords (CRITICAL)
        (r'password\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', "password", SensitivityLevel.CRITICAL),
        (r'passwd\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', "password", SensitivityLevel.CRITICAL),
        (r'secret\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]', "secret", SensitivityLevel.HIGH),
        
        # Private keys
        (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "private_key", SensitivityLevel.CRITICAL),
        
        # JWTs
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "jwt", SensitivityLevel.HIGH),
        
        # Database strings
        (r'(mongodb(\+srv)?://[^\'"`\s]+)', "mongodb_uri", SensitivityLevel.CRITICAL),
        (r'(postgres://[^\'"`\s]+)', "postgres_uri", SensitivityLevel.CRITICAL),
        (r'(mysql://[^\'"`\s]+)', "mysql_uri", SensitivityLevel.CRITICAL),
        (r'(redis://[^\'"`\s]+)', "redis_uri", SensitivityLevel.HIGH),
    ]
    
    # Auth flow patterns
    AUTH_PATTERNS = [
        r'login|signin|authenticate',
        r'logout|signout',
        r'register|signup',
        r'password|passwd',
        r'oauth|sso|saml',
        r'jwt|bearer|authorization',
        r'session|cookie',
        r'token|refresh',
    ]
    
    # Admin/privilege patterns
    ADMIN_PATTERNS = [
        r'/admin',
        r'/dashboard',
        r'/manage',
        r'/settings',
        r'/config',
        r'isAdmin|is_admin|hasRole|hasPermission',
        r'role\s*[:=]\s*[\'"`](admin|superuser|root)',
        r'permission|privilege|access[_-]?level',
    ]
    
    # Framework detection
    FRAMEWORK_PATTERNS = {
        "react": [r'React\.', r'useState|useEffect', r'createRoot', r'ReactDOM'],
        "angular": [r'@angular', r'NgModule', r'Component\(', r'Injectable'],
        "vue": [r'Vue\.', r'createApp', r'v-model', r'v-if'],
        "jquery": [r'\$\(', r'jQuery'],
        "next": [r'next/router', r'getServerSideProps', r'getStaticProps'],
        "nuxt": [r'nuxt', r'\$nuxt'],
    }
    
    def __init__(self):
        self.analysis = JSAnalysis()
    
    def analyze_file(self, content: str, filename: str) -> JSAnalysis:
        """Analyze a single JS file"""
        analysis = JSAnalysis()
        
        # Extract endpoints
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get the URL (last group usually)
                url = match.groups()[-1]
                if self._is_valid_endpoint(url):
                    # Determine method
                    method = "GET"
                    full_match = match.group(0).lower()
                    if "post" in full_match:
                        method = "POST"
                    elif "put" in full_match:
                        method = "PUT"
                    elif "delete" in full_match:
                        method = "DELETE"
                    
                    endpoint = Endpoint(
                        url=url,
                        method=method,
                        source_file=filename,
                        context=self._get_context(content, match.start())
                    )
                    
                    # Check if auth-related
                    context = endpoint.context.lower()
                    if any(re.search(p, context) for p in self.AUTH_PATTERNS):
                        endpoint.auth_required = True
                    
                    analysis.endpoints.append(endpoint)
        
        # Extract secrets
        for pattern, secret_type, sensitivity in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                value = match.group(1) if match.lastindex else match.group(0)
                
                # Skip false positives
                if self._is_false_positive_secret(value):
                    continue
                
                secret = Secret(
                    type=secret_type,
                    value=value,
                    source_file=filename,
                    line=content[:match.start()].count('\n') + 1,
                    sensitivity=sensitivity,
                    context=self._get_context(content, match.start())
                )
                analysis.secrets.append(secret)
        
        # Detect frameworks
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    if framework not in analysis.frameworks:
                        analysis.frameworks.append(framework)
                    break
        
        # Extract domains
        domain_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.[-a-zA-Z0-9.]+)'
        for match in re.finditer(domain_pattern, content):
            analysis.domains.add(match.group(1))
        
        # Check for source maps
        if ".map" in content or "sourceMappingURL" in content:
            map_pattern = r'sourceMappingURL=([^\s\'\"]+)'
            for match in re.finditer(map_pattern, content):
                analysis.source_maps.append(match.group(1))
        
        # Detect flows
        analysis.flows = self._detect_flows(content, analysis.endpoints, filename)
        
        return analysis
    
    def _is_valid_endpoint(self, url: str) -> bool:
        """Check if extracted URL is a valid endpoint"""
        # Skip obvious non-endpoints
        invalid = [
            "javascript:", "mailto:", "tel:", "data:",
            ".css", ".png", ".jpg", ".gif", ".svg",
            "undefined", "null", "true", "false",
        ]
        url_lower = url.lower()
        for inv in invalid:
            if inv in url_lower:
                return False
        
        # Must look like a path or URL
        if url.startswith("/") or url.startswith("http") or "api" in url_lower:
            return True
        
        return False
    
    def _is_false_positive_secret(self, value: str) -> bool:
        """Check if secret is likely a false positive"""
        # Too short
        if len(value) < 8:
            return True
        
        # Common placeholders
        placeholders = [
            "your_", "xxx", "placeholder", "example",
            "changeme", "secret", "password123", "test",
            "demo", "sample", "dummy", "fake"
        ]
        value_lower = value.lower()
        for p in placeholders:
            if p in value_lower:
                return True
        
        # All same character
        if len(set(value)) <= 2:
            return True
        
        return False
    
    def _get_context(self, content: str, pos: int, chars: int = 100) -> str:
        """Get code context around a position"""
        start = max(0, pos - chars)
        end = min(len(content), pos + chars)
        return content[start:end].replace('\n', ' ').strip()
    
    def _detect_flows(self, content: str, endpoints: List[Endpoint], filename: str) -> List[Flow]:
        """Detect application flows from code structure"""
        flows = []
        
        # Auth flow detection
        if any(re.search(p, content, re.IGNORECASE) for p in self.AUTH_PATTERNS):
            auth_endpoints = [e for e in endpoints if e.auth_required]
            if auth_endpoints:
                flow = Flow(
                    type=FlowType.AUTH,
                    name="Authentication Flow",
                    steps=[
                        "1. User submits credentials",
                        "2. Server validates",
                        "3. Token/session created"
                    ],
                    endpoints=auth_endpoints,
                    requires_auth=False,
                    description="User authentication mechanism detected",
                    attack_potential="Test for: credential stuffing, brute force, auth bypass, token theft"
                )
                flows.append(flow)
        
        # Admin flow detection
        admin_matches = []
        for pattern in self.ADMIN_PATTERNS:
            admin_matches.extend(re.finditer(pattern, content, re.IGNORECASE))
        
        if admin_matches:
            admin_endpoints = [e for e in endpoints if "/admin" in e.url.lower() or "/manage" in e.url.lower()]
            flow = Flow(
                type=FlowType.ADMIN,
                name="Admin Functionality",
                steps=[
                    "1. Access admin endpoint",
                    "2. Perform privileged action",
                    "3. Modify system state"
                ],
                endpoints=admin_endpoints,
                requires_auth=True,
                privilege_level="admin",
                description="Administrative functionality detected",
                attack_potential="Test for: auth bypass, privilege escalation, IDOR"
            )
            flows.append(flow)
        
        # File operation detection
        file_patterns = [r'upload|download|file|attachment|document|image']
        if any(re.search(p, content, re.IGNORECASE) for p in file_patterns):
            file_endpoints = [e for e in endpoints if any(
                x in e.url.lower() for x in ['upload', 'download', 'file', 'attachment']
            )]
            if file_endpoints:
                flow = Flow(
                    type=FlowType.FILE_OP,
                    name="File Operations",
                    steps=[
                        "1. User selects file",
                        "2. File uploaded/downloaded",
                        "3. Server processes"
                    ],
                    endpoints=file_endpoints,
                    description="File handling functionality detected",
                    attack_potential="Test for: unrestricted upload, path traversal, SSRF"
                )
                flows.append(flow)
        
        # Data submission flow
        post_endpoints = [e for e in endpoints if e.method == "POST"]
        if len(post_endpoints) > 2:
            flow = Flow(
                type=FlowType.DATA_SUBMIT,
                name="Data Submission",
                steps=[
                    "1. User fills form",
                    "2. Data submitted via POST",
                    "3. Server processes and stores"
                ],
                endpoints=post_endpoints,
                description=f"{len(post_endpoints)} POST endpoints found",
                attack_potential="Test for: injection, XSS, business logic"
            )
            flows.append(flow)
        
        return flows
    
    def analyze_directory(self, js_dir: Path) -> JSAnalysis:
        """Analyze all JS files in a directory"""
        combined = JSAnalysis()
        
        for js_file in js_dir.glob("**/*.js"):
            try:
                content = js_file.read_text(errors='ignore')
                file_analysis = self.analyze_file(content, str(js_file.name))
                
                # Merge results
                combined.endpoints.extend(file_analysis.endpoints)
                combined.secrets.extend(file_analysis.secrets)
                combined.flows.extend(file_analysis.flows)
                combined.domains.update(file_analysis.domains)
                combined.frameworks.extend(file_analysis.frameworks)
                combined.source_maps.extend(file_analysis.source_maps)
                
            except Exception as e:
                continue
        
        # Deduplicate
        combined.frameworks = list(set(combined.frameworks))
        
        self.analysis = combined
        return combined
    
    def generate_report(self) -> str:
        """Generate human-readable intelligence report"""
        a = self.analysis
        
        lines = [
            "═══════════════════════════════════════════════════════════════════",
            "                    JAVASCRIPT INTELLIGENCE REPORT                  ",
            "═══════════════════════════════════════════════════════════════════",
            "",
            f"📊 Summary:",
            f"   • Endpoints: {len(a.endpoints)}",
            f"   • Secrets: {len(a.secrets)} ({len([s for s in a.secrets if s.sensitivity.value >= 3])} HIGH/CRITICAL)",
            f"   • Flows: {len(a.flows)}",
            f"   • Domains: {len(a.domains)}",
            f"   • Frameworks: {', '.join(a.frameworks) or 'Unknown'}",
            f"   • Source Maps: {len(a.source_maps)}",
            "",
        ]
        
        # Critical secrets first
        critical_secrets = [s for s in a.secrets if s.sensitivity == SensitivityLevel.CRITICAL]
        if critical_secrets:
            lines.append("🚨 CRITICAL SECRETS FOUND:")
            for secret in critical_secrets:
                lines.append(f"   [{secret.type}] {secret.masked_value()}")
                lines.append(f"      File: {secret.source_file}:{secret.line}")
            lines.append("")
        
        # High-value flows
        high_value_flows = [f for f in a.flows if f.type in [FlowType.AUTH, FlowType.ADMIN]]
        if high_value_flows:
            lines.append("🎯 HIGH-VALUE FLOWS:")
            for flow in high_value_flows:
                lines.append(f"   [{flow.type.value.upper()}] {flow.name}")
                lines.append(f"      {flow.description}")
                lines.append(f"      Attack: {flow.attack_potential}")
                if flow.endpoints:
                    lines.append(f"      Endpoints: {len(flow.endpoints)}")
            lines.append("")
        
        # Auth-required endpoints
        auth_endpoints = [e for e in a.endpoints if e.auth_required]
        if auth_endpoints:
            lines.append("🔐 AUTH-REQUIRED ENDPOINTS:")
            for ep in auth_endpoints[:10]:  # Top 10
                lines.append(f"   [{ep.method}] {ep.url}")
            if len(auth_endpoints) > 10:
                lines.append(f"   ... and {len(auth_endpoints) - 10} more")
            lines.append("")
        
        # Admin endpoints
        admin_endpoints = [e for e in a.endpoints if "/admin" in e.url.lower()]
        if admin_endpoints:
            lines.append("👑 ADMIN ENDPOINTS:")
            for ep in admin_endpoints:
                lines.append(f"   [{ep.method}] {ep.url}")
            lines.append("")
        
        # Source maps
        if a.source_maps:
            lines.append("📜 SOURCE MAPS AVAILABLE:")
            for sm in a.source_maps[:5]:
                lines.append(f"   {sm}")
            lines.append("   → Download and reconstruct original source!")
            lines.append("")
        
        # Recommendations
        lines.append("═══════════════════════════════════════════════════════════════════")
        lines.append("                         RECOMMENDATIONS                            ")
        lines.append("═══════════════════════════════════════════════════════════════════")
        
        if critical_secrets:
            lines.append("1. ⚠️  Validate and test all discovered secrets IMMEDIATELY")
        
        if high_value_flows:
            lines.append("2. 🎯 Focus manual testing on auth and admin flows")
        
        if a.source_maps:
            lines.append("3. 📜 Download source maps and analyze original code")
        
        if len(auth_endpoints) > 5:
            lines.append("4. 🔐 Map complete auth surface - look for bypass opportunities")
        
        return "\n".join(lines)

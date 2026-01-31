#!/usr/bin/env python3
"""
SHADOW - Scoring System

Rule-based scoring. كل نقطة لها سبب.
"""

import re
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ScoreResult:
    """نتيجة الـ scoring"""
    total: int
    reasons: List[str]
    tags: List[str]


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING RULES
# ═══════════════════════════════════════════════════════════════════════════════

# Parameters that indicate vulnerabilities
PARAM_SCORES = {
    # IDOR candidates
    'id': (3, 'idor', 'Sequential ID parameter'),
    'user_id': (4, 'idor', 'User ID - IDOR candidate'),
    'account_id': (4, 'idor', 'Account ID - IDOR candidate'),
    'order_id': (3, 'idor', 'Order ID - IDOR candidate'),
    'doc_id': (3, 'idor', 'Document ID - IDOR candidate'),
    'file_id': (3, 'idor', 'File ID - IDOR candidate'),

    # SSRF/Redirect candidates
    'url': (4, 'ssrf', 'URL parameter - SSRF candidate'),
    'redirect': (4, 'redirect', 'Redirect parameter - Open Redirect'),
    'next': (3, 'redirect', 'Next URL - Open Redirect'),
    'return': (3, 'redirect', 'Return URL - Open Redirect'),
    'returnto': (3, 'redirect', 'ReturnTo - Open Redirect'),
    'goto': (3, 'redirect', 'Goto parameter - Open Redirect'),
    'dest': (3, 'redirect', 'Destination - SSRF/Redirect'),
    'target': (3, 'ssrf', 'Target URL - SSRF candidate'),
    'uri': (3, 'ssrf', 'URI parameter - SSRF candidate'),
    'path': (3, 'ssrf', 'Path parameter - SSRF/LFI'),
    'callback': (3, 'ssrf', 'Callback URL - SSRF'),
    'webhook': (4, 'ssrf', 'Webhook URL - SSRF'),

    # LFI candidates
    'file': (4, 'lfi', 'File parameter - LFI candidate'),
    'filename': (4, 'lfi', 'Filename - LFI candidate'),
    'filepath': (5, 'lfi', 'Filepath - LFI candidate'),
    'page': (3, 'lfi', 'Page parameter - LFI candidate'),
    'include': (5, 'lfi', 'Include parameter - LFI candidate'),
    'template': (4, 'lfi', 'Template - LFI/SSTI candidate'),
    'document': (3, 'lfi', 'Document path - LFI candidate'),

    # XSS candidates
    'search': (2, 'xss', 'Search parameter - XSS candidate'),
    'query': (2, 'xss', 'Query parameter - XSS candidate'),
    'q': (2, 'xss', 'Search query - XSS candidate'),
    'name': (2, 'xss', 'Name field - XSS candidate'),
    'message': (2, 'xss', 'Message field - XSS candidate'),
    'comment': (2, 'xss', 'Comment field - XSS candidate'),
    'body': (2, 'xss', 'Body content - XSS candidate'),
    'content': (2, 'xss', 'Content field - XSS candidate'),
    'title': (2, 'xss', 'Title field - XSS candidate'),
    'description': (2, 'xss', 'Description - XSS candidate'),
    'error': (2, 'xss', 'Error message - XSS candidate'),

    # SQLi candidates
    'sort': (3, 'sqli', 'Sort parameter - SQLi candidate'),
    'order': (3, 'sqli', 'Order parameter - SQLi candidate'),
    'orderby': (3, 'sqli', 'OrderBy - SQLi candidate'),
    'filter': (3, 'sqli', 'Filter parameter - SQLi candidate'),
    'where': (4, 'sqli', 'Where clause - SQLi candidate'),
    'column': (3, 'sqli', 'Column parameter - SQLi candidate'),
    'table': (4, 'sqli', 'Table parameter - SQLi candidate'),
    'field': (2, 'sqli', 'Field parameter - SQLi candidate'),

    # Command injection
    'cmd': (5, 'rce', 'Command parameter - RCE candidate'),
    'exec': (5, 'rce', 'Exec parameter - RCE candidate'),
    'command': (5, 'rce', 'Command parameter - RCE candidate'),
    'execute': (5, 'rce', 'Execute parameter - RCE candidate'),
    'ping': (4, 'rce', 'Ping parameter - RCE candidate'),
    'host': (3, 'rce', 'Host parameter - Injection candidate'),
    'ip': (3, 'rce', 'IP parameter - Injection candidate'),

    # Serialization
    'data': (2, 'deserialization', 'Data parameter - check format'),
    'object': (3, 'deserialization', 'Object parameter - deserialization'),
    'payload': (3, 'deserialization', 'Payload - deserialization candidate'),

    # Auth related
    'token': (3, 'auth', 'Token parameter - check validation'),
    'api_key': (3, 'auth', 'API key - check exposure'),
    'auth': (2, 'auth', 'Auth parameter'),
    'password': (3, 'auth', 'Password parameter'),
    'secret': (4, 'auth', 'Secret parameter'),
}

# Path patterns that increase score
PATH_SCORES = [
    (r'/api/', 3, 'api', 'API endpoint'),
    (r'/v\d+/', 2, 'api', 'Versioned API'),
    (r'/internal/', 4, 'internal', 'Internal endpoint'),
    (r'/admin', 4, 'admin', 'Admin path'),
    (r'/dashboard', 3, 'admin', 'Dashboard'),
    (r'/manage', 3, 'admin', 'Management interface'),
    (r'/config', 4, 'config', 'Configuration endpoint'),
    (r'/settings', 3, 'config', 'Settings endpoint'),
    (r'/debug', 5, 'debug', 'Debug endpoint'),
    (r'/test', 2, 'debug', 'Test endpoint'),
    (r'/dev', 3, 'debug', 'Development endpoint'),
    (r'/staging', 3, 'internal', 'Staging endpoint'),
    (r'/backup', 4, 'exposure', 'Backup path'),
    (r'/upload', 3, 'upload', 'Upload endpoint'),
    (r'/import', 3, 'upload', 'Import endpoint'),
    (r'/export', 2, 'exposure', 'Export endpoint'),
    (r'/download', 2, 'lfi', 'Download endpoint'),
    (r'/graphql', 4, 'graphql', 'GraphQL endpoint'),
    (r'/webhook', 3, 'ssrf', 'Webhook endpoint'),
    (r'/callback', 3, 'ssrf', 'Callback endpoint'),
    (r'/proxy', 4, 'ssrf', 'Proxy endpoint'),
    (r'/redirect', 3, 'redirect', 'Redirect endpoint'),
    (r'/oauth', 3, 'auth', 'OAuth endpoint'),
    (r'/login', 2, 'auth', 'Login endpoint'),
    (r'/register', 2, 'auth', 'Registration endpoint'),
    (r'/reset', 2, 'auth', 'Password reset'),
    (r'/forgot', 2, 'auth', 'Forgot password'),
    (r'/2fa', 3, 'auth', '2FA endpoint'),
    (r'/mfa', 3, 'auth', 'MFA endpoint'),
    (r'\.git', 5, 'exposure', 'Git exposure'),
    (r'\.env', 5, 'exposure', 'Env file exposure'),
    (r'\.bak', 4, 'exposure', 'Backup file'),
    (r'\.old', 3, 'exposure', 'Old file'),
    (r'\.zip', 3, 'exposure', 'Archive file'),
    (r'/swagger', 4, 'api', 'Swagger documentation'),
    (r'/openapi', 4, 'api', 'OpenAPI documentation'),
    (r'/docs', 2, 'api', 'Documentation'),
    (r'/actuator', 5, 'exposure', 'Spring Actuator'),
    (r'/metrics', 3, 'exposure', 'Metrics endpoint'),
    (r'/health', 2, 'exposure', 'Health endpoint'),
    (r'/status', 2, 'exposure', 'Status endpoint'),
    (r'/info', 2, 'exposure', 'Info endpoint'),
    (r'/console', 4, 'admin', 'Console access'),
    (r'/shell', 5, 'rce', 'Shell access'),
    (r'/exec', 5, 'rce', 'Exec endpoint'),
    (r'/run', 4, 'rce', 'Run endpoint'),
    (r'/cgi-bin', 3, 'rce', 'CGI endpoint'),
    (r'/ws', 2, 'websocket', 'WebSocket endpoint'),
    (r'/socket', 2, 'websocket', 'Socket endpoint'),
]

# Technology bonuses
TECH_SCORES = {
    'php': (2, 'Classic vulns common'),
    'asp': (2, 'Windows-specific vulns'),
    'jsp': (2, 'Java vulns'),
    'java': (2, 'Deserialization risks'),
    'spring': (3, 'Spring4Shell, Actuator'),
    'struts': (4, 'OGNL injection history'),
    'wordpress': (3, 'Plugin vulnerabilities'),
    'drupal': (3, 'Drupalgeddon variants'),
    'joomla': (2, 'Known CVEs'),
    'jenkins': (4, 'Groovy RCE, credentials'),
    'gitlab': (3, 'CI/CD secrets, RCE CVEs'),
    'jira': (3, 'SSRF, user enum'),
    'confluence': (4, 'Recent RCE CVEs'),
    'tomcat': (2, 'Manager app, CVEs'),
    'weblogic': (4, 'Deserialization RCE'),
    'coldfusion': (3, 'Known CVEs'),
    'elasticsearch': (4, 'Open clusters'),
    'kibana': (3, 'RCE vulnerabilities'),
    'grafana': (3, 'Path traversal, auth bypass'),
    'mongodb': (3, 'NoSQL injection'),
    'redis': (3, 'Unauthenticated access'),
    'graphql': (3, 'Introspection, batching'),
}

# Noise patterns - reduce score
NOISE_PATTERNS = [
    (r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$', -5, 'Static file'),
    (r'/(static|assets|images|img|css|js|fonts|media)/', -3, 'Static directory'),
    (r'cloudfront\.net', -4, 'CDN domain'),
    (r'cloudflare', -3, 'CDN domain'),
    (r'akamai', -4, 'CDN domain'),
    (r'fastly', -3, 'CDN domain'),
    (r'amazonaws\.com', -2, 'AWS hosted'),
    (r'azurewebsites\.net', -2, 'Azure hosted'),
    (r'herokuapp\.com', -2, 'Heroku hosted'),
    (r'for\s*sale|parked|coming\s*soon', -5, 'Parked domain'),
    (r'404|not\s*found', -2, 'Dead page'),
]


# ═══════════════════════════════════════════════════════════════════════════════
# SCORER
# ═══════════════════════════════════════════════════════════════════════════════

class Scorer:
    """Calculate interesting score for endpoints"""

    def score_endpoint(self, path: str, params: Dict[str, str] = None,
                       technology: str = "", title: str = "") -> ScoreResult:
        """
        Score an endpoint based on path, params, and context.
        
        Returns ScoreResult with total score, reasons, and tags.
        """
        total = 0
        reasons = []
        tags = set()
        params = params or {}

        path_lower = path.lower()
        tech_lower = technology.lower()
        title_lower = title.lower()

        # ─────────────────────────────────────────────────────────────────────
        # Score parameters
        # ─────────────────────────────────────────────────────────────────────
        for param_name in params.keys():
            param_lower = param_name.lower()

            # Exact match
            if param_lower in PARAM_SCORES:
                score, tag, reason = PARAM_SCORES[param_lower]
                total += score
                reasons.append(f"+{score}: {reason} ({param_name})")
                tags.add(tag)
            else:
                # Partial match
                for key, (score, tag, reason) in PARAM_SCORES.items():
                    if key in param_lower:
                        total += score - 1  # Slightly lower for partial
                        reasons.append(f"+{score-1}: {reason} (partial: {param_name})")
                        tags.add(tag)
                        break

        # ─────────────────────────────────────────────────────────────────────
        # Score path patterns
        # ─────────────────────────────────────────────────────────────────────
        for pattern, score, tag, reason in PATH_SCORES:
            if re.search(pattern, path_lower):
                total += score
                reasons.append(f"+{score}: {reason}")
                tags.add(tag)

        # ─────────────────────────────────────────────────────────────────────
        # Score technology
        # ─────────────────────────────────────────────────────────────────────
        for tech, (score, reason) in TECH_SCORES.items():
            if tech in tech_lower:
                total += score
                reasons.append(f"+{score}: {tech.upper()} - {reason}")
                tags.add(tech)

        # ─────────────────────────────────────────────────────────────────────
        # Apply noise penalties
        # ─────────────────────────────────────────────────────────────────────
        full_context = f"{path_lower} {title_lower} {tech_lower}"

        for pattern, penalty, reason in NOISE_PATTERNS:
            if re.search(pattern, full_context):
                total += penalty  # penalty is negative
                reasons.append(f"{penalty}: {reason}")
                tags.add('noise')

        # ─────────────────────────────────────────────────────────────────────
        # Bonus: multiple param types = more interesting
        # ─────────────────────────────────────────────────────────────────────
        vuln_tags = {'idor', 'ssrf', 'lfi', 'xss', 'sqli', 'rce'}
        found_vuln_tags = tags & vuln_tags

        if len(found_vuln_tags) >= 2:
            bonus = len(found_vuln_tags)
            total += bonus
            reasons.append(f"+{bonus}: Multiple vuln indicators ({', '.join(found_vuln_tags)})")

        # Minimum score is 0
        total = max(0, total)

        return ScoreResult(
            total=total,
            reasons=reasons,
            tags=list(tags)
        )

    def score_asset(self, domain: str, services: List = None) -> ScoreResult:
        """Score an asset (domain) based on its characteristics"""
        total = 0
        reasons = []
        tags = set()

        domain_lower = domain.lower()

        # Internal naming patterns
        internal_patterns = [
            (r'^(dev|staging|test|qa|uat|internal|corp|vpn|admin)', 3, 'internal'),
            (r'^api\.', 2, 'api'),
            (r'^admin\.', 3, 'admin'),
            (r'^portal\.', 2, 'admin'),
            (r'^dashboard\.', 2, 'admin'),
            (r'^backend\.', 3, 'internal'),
            (r'^jenkins\.', 4, 'ci'),
            (r'^gitlab\.', 3, 'ci'),
            (r'^jira\.', 2, 'internal'),
            (r'^confluence\.', 2, 'internal'),
            (r'^grafana\.', 3, 'monitoring'),
            (r'^kibana\.', 3, 'monitoring'),
            (r'^elastic', 3, 'monitoring'),
            (r'^mongo', 3, 'database'),
            (r'^redis', 3, 'database'),
            (r'^db\.', 4, 'database'),
            (r'^sql', 3, 'database'),
            (r'^mysql', 3, 'database'),
            (r'^postgres', 3, 'database'),
        ]

        for pattern, score, tag in internal_patterns:
            if re.search(pattern, domain_lower):
                total += score
                reasons.append(f"+{score}: {tag.upper()} subdomain pattern")
                tags.add(tag)

        return ScoreResult(
            total=total,
            reasons=reasons,
            tags=list(tags)
        )


# ═══════════════════════════════════════════════════════════════════════════════
# PRIORITY CALCULATOR
# ═══════════════════════════════════════════════════════════════════════════════

def get_priority(score: int) -> str:
    """Convert score to priority label"""
    if score >= 10:
        return "critical"
    elif score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    elif score > 0:
        return "low"
    else:
        return "noise"


def get_action_suggestion(score: int, tags: List[str], findings: List[str] = None) -> str:
    """
    Get recommended action based on score, tags, and findings.
    
    Returns: deep-scan, xss-test, sqli-test, ssrf-test, manual-review, ignore, etc.
    """
    findings = findings or []
    tags_set = set(tags)

    # If already has high-severity findings, verify/exploit
    if findings:
        if any('critical' in f.lower() or 'high' in f.lower() for f in findings):
            return "exploit-verify"

    # Immediate priority based on vulnerability type
    if 'rce' in tags_set:
        return "rce-test"
    if 'sqli' in tags_set:
        return "sqli-test"
    if 'lfi' in tags_set:
        return "lfi-test"
    if 'ssrf' in tags_set:
        return "ssrf-test"
    if 'xss' in tags_set:
        return "xss-test"
    if 'idor' in tags_set:
        return "idor-test"
    if 'auth' in tags_set:
        return "auth-bypass-test"
    if 'admin' in tags_set:
        return "admin-access-test"
    if 'exposure' in tags_set:
        return "info-leak-check"
    if 'graphql' in tags_set:
        return "graphql-introspection"
    if 'api' in tags_set:
        return "api-fuzz"

    # Score-based fallback
    if score >= 10:
        return "deep-scan"
    elif score >= 7:
        return "targeted-scan"
    elif score >= 4:
        return "light-scan"
    elif score > 0:
        return "monitor"

    return "ignore"


# ═══════════════════════════════════════════════════════════════════════════════
# HEURISTIC RULES
# ═══════════════════════════════════════════════════════════════════════════════

class HeuristicRules:
    """
    Rule-based heuristics for prioritization decisions.
    
    Each rule returns (should_escalate: bool, reason: str)
    """

    @staticmethod
    def nuclei_severity_escalation(finding: Dict) -> tuple:
        """If nuclei found severity >= high, immediate priority"""
        severity = finding.get('severity', 'info').lower()
        if severity in ('high', 'critical'):
            return True, f"Nuclei finding: {severity} severity"
        return False, ""

    @staticmethod
    def auth_surface_detection(service: Dict, endpoint: Dict) -> tuple:
        """Detect authentication surfaces for focused testing"""
        # Check for auth cookies
        headers = service.get('headers', {})
        cookies = headers.get('set-cookie', '').lower()

        has_secure_cookie = 'secure' in cookies and 'httponly' in cookies
        has_auth = any(k in cookies for k in ['session', 'token', 'auth', 'jwt'])

        path = endpoint.get('path', '').lower()
        is_auth_endpoint = any(p in path for p in ['/login', '/auth', '/oauth', '/register'])

        if has_auth or is_auth_endpoint:
            return True, "auth-surface: Authentication mechanism detected"
        return False, ""

    @staticmethod
    def interesting_technology(technology: str) -> tuple:
        """Detect high-value technologies"""
        tech_lower = technology.lower()

        high_value = {
            'jenkins': 'CI/CD system - check for RCE, credential exposure',
            'gitlab': 'Source control - check for repo access, CI secrets',
            'confluence': 'Wiki - recent RCE CVEs, check version',
            'struts': 'Java framework - OGNL injection history',
            'weblogic': 'App server - deserialization vulnerabilities',
            'spring': 'Java framework - Spring4Shell, Actuator',
        }

        for tech, reason in high_value.items():
            if tech in tech_lower:
                return True, f"high-value-tech: {tech.upper()} - {reason}"

        return False, ""

    @staticmethod
    def parameter_density(params: Dict) -> tuple:
        """High parameter count often indicates complex attack surface"""
        if len(params) >= 5:
            return True, f"high-param-density: {len(params)} parameters"
        return False, ""

    @staticmethod
    def debug_exposure(path: str, title: str) -> tuple:
        """Detect debug/development exposure"""
        context = f"{path} {title}".lower()

        debug_indicators = ['debug', 'trace', 'stack', 'error', 'exception', 'phpinfo']

        for indicator in debug_indicators:
            if indicator in context:
                return True, f"debug-exposure: '{indicator}' detected"

        return False, ""


def apply_heuristics(
    endpoint: Dict,
    service: Dict = None,
    findings: List[Dict] = None
) -> List[str]:
    """
    Apply all heuristic rules and return list of escalation reasons.
    """
    reasons = []
    service = service or {}
    findings = findings or []

    # Check nuclei findings
    for finding in findings:
        escalate, reason = HeuristicRules.nuclei_severity_escalation(finding)
        if escalate:
            reasons.append(reason)

    # Check auth surface
    escalate, reason = HeuristicRules.auth_surface_detection(service, endpoint)
    if escalate:
        reasons.append(reason)

    # Check technology
    tech = service.get('technology', '') or endpoint.get('technology', '')
    escalate, reason = HeuristicRules.interesting_technology(tech)
    if escalate:
        reasons.append(reason)

    # Check parameter density
    params = endpoint.get('params', {})
    escalate, reason = HeuristicRules.parameter_density(params)
    if escalate:
        reasons.append(reason)

    # Check debug exposure
    path = endpoint.get('path', '')
    title = service.get('title', '') or endpoint.get('title', '')
    escalate, reason = HeuristicRules.debug_exposure(path, title)
    if escalate:
        reasons.append(reason)

    return reasons


def format_target(target: Dict) -> str:
    """Format a target for display"""
    priority = get_priority(target.get('score', 0))

    icon = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'noise': '⚫'
    }.get(priority, '⚪')

    lines = [
        f"{icon} [{priority.upper()}] Score: {target.get('score', 0)}",
        f"   URL: {target.get('url', '')}",
    ]

    if target.get('technology'):
        lines.append(f"   Tech: {target.get('technology')}")

    if target.get('title'):
        lines.append(f"   Title: {target.get('title')[:50]}")

    if target.get('params'):
        params = list(target['params'].keys())[:5]
        lines.append(f"   Params: {', '.join(params)}")

    if target.get('tags'):
        lines.append(f"   Tags: {', '.join(target['tags'][:5])}")

    if target.get('findings'):
        lines.append(f"   Findings: {', '.join(target['findings'])}")

    return '\n'.join(lines)

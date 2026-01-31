"""
SHADOW v6 - Output Generator

Instead of 10,000 URLs:
- Top 20 Targets
- Why each is interesting
- Suggested attack paths
- Actionable intelligence
"""

import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path

from .state import TargetState, StateManager
from .scorer import Scorer, Score


@dataclass
class AttackPath:
    """A suggested attack path"""
    name: str
    steps: List[str]
    tools: List[str]
    success_indicators: List[str]
    estimated_time: str  # "5min", "1hr", etc.


@dataclass
class TargetReport:
    """Report for a single target"""
    domain: str
    score: int
    priority: str
    why_interesting: List[str]
    attack_surface: Dict[str, Any]
    attack_paths: List[AttackPath]
    quick_wins: List[str]
    notes: List[str]


class OutputGenerator:
    """
    Generates actionable, human-readable output.
    
    Philosophy:
    - Quality over quantity
    - Every item must be actionable
    - Time estimates for manual testing
    - Clear attack paths
    """
    
    def __init__(self, state_manager: StateManager, output_dir: Path):
        self.state_manager = state_manager
        self.output_dir = Path(output_dir)
        self.scorer = Scorer()
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_target_report(self, state: TargetState) -> TargetReport:
        """Generate report for a single target"""
        score = self.scorer.calculate(state)
        
        # Why is this interesting?
        why_interesting = []
        for factor in score.factors:
            if factor.points > 0:
                why_interesting.append(f"{factor.name}: {factor.reason}")
        
        # Build attack surface summary
        attack_surface = {
            "subdomains": state.subdomains_count,
            "alive_hosts": len(state.alive_hosts),
            "technologies": state.fingerprint.technologies[:5],
            "waf": state.waf.value,
            "auth": {
                "login": state.auth.has_login,
                "oauth": state.auth.has_oauth,
                "jwt": state.auth.has_jwt
            },
            "api": {
                "detected": state.api.detected,
                "type": state.api.type,
                "endpoints": state.api.endpoints_count
            },
            "params": {
                "total": state.params.total_count,
                "xss_candidates": len(state.params.xss_candidates),
                "sqli_candidates": len(state.params.sqli_candidates),
                "ssrf_candidates": len(state.params.ssrf_candidates),
                "idor_candidates": len(state.params.idor_candidates)
            },
            "js": {
                "endpoints": state.js.endpoints_found,
                "secrets": state.js.secrets_found,
                "source_maps": state.js.source_maps
            }
        }
        
        # Generate attack paths
        attack_paths = self._generate_attack_paths(state, score)
        
        # Quick wins
        quick_wins = self._identify_quick_wins(state)
        
        return TargetReport(
            domain=state.domain,
            score=score.total,
            priority=score.priority,
            why_interesting=why_interesting[:5],  # Top 5 reasons
            attack_surface=attack_surface,
            attack_paths=attack_paths,
            quick_wins=quick_wins,
            notes=state.notes[-5:]  # Last 5 notes
        )
    
    def _generate_attack_paths(self, state: TargetState, score: Score) -> List[AttackPath]:
        """Generate suggested attack paths based on findings"""
        paths = []
        
        # Auth bypass path
        if state.auth.has_login:
            paths.append(AttackPath(
                name="Authentication Testing",
                steps=[
                    "1. Identify login endpoint",
                    "2. Test default credentials",
                    "3. Test rate limiting",
                    "4. Test for auth bypass (SQLi, response manipulation)",
                    "5. Test password reset flow"
                ],
                tools=["Burp Suite", "ffuf (for brute force)", "sqlmap (if error-based)"],
                success_indicators=[
                    "Access without valid credentials",
                    "Account enumeration",
                    "Rate limit bypass"
                ],
                estimated_time="1-2 hours"
            ))
        
        # JWT attack path
        if state.auth.has_jwt:
            paths.append(AttackPath(
                name="JWT Exploitation",
                steps=[
                    "1. Capture JWT token",
                    "2. Decode and analyze claims",
                    "3. Test alg:none vulnerability",
                    "4. Test HS256/RS256 confusion",
                    "5. Bruteforce weak secrets (jwt_tool)",
                    "6. Test claim manipulation (user_id, role)"
                ],
                tools=["jwt_tool", "Burp JWT extension", "hashcat"],
                success_indicators=[
                    "Forged token accepted",
                    "Privilege escalation via claims"
                ],
                estimated_time="30min - 1 hour"
            ))
        
        # GraphQL path
        if state.api.type == "graphql":
            paths.append(AttackPath(
                name="GraphQL Exploitation",
                steps=[
                    "1. Run introspection query",
                    "2. Map all queries and mutations",
                    "3. Identify hidden/admin mutations",
                    "4. Test for nested query DoS",
                    "5. Test for IDOR in query arguments",
                    "6. Test batching attacks"
                ],
                tools=["GraphQL Voyager", "InQL Burp extension", "graphql-cop"],
                success_indicators=[
                    "Access to admin mutations",
                    "Data leakage via introspection",
                    "IDOR in queries"
                ],
                estimated_time="1-2 hours"
            ))
        
        # IDOR path
        if state.params.idor_candidates:
            paths.append(AttackPath(
                name="IDOR Exploitation",
                steps=[
                    "1. Create two test accounts",
                    "2. Identify ID parameters",
                    "3. Replace IDs between accounts",
                    "4. Test enumeration (sequential IDs)",
                    "5. Test for UUID prediction if applicable"
                ],
                tools=["Burp Suite", "Autorize extension"],
                success_indicators=[
                    "Access to other users' data",
                    "Modify other users' resources"
                ],
                estimated_time="30min - 1 hour"
            ))
        
        # SSRF path
        if state.params.ssrf_candidates:
            paths.append(AttackPath(
                name="SSRF Exploitation",
                steps=[
                    "1. Identify URL/host parameters",
                    "2. Test with external collaborator",
                    "3. Test internal IP access (127.0.0.1, 169.254.169.254)",
                    "4. Test protocol handlers (file://, gopher://)",
                    "5. Test for cloud metadata access"
                ],
                tools=["Burp Collaborator", "SSRFmap"],
                success_indicators=[
                    "Internal network access",
                    "Cloud metadata retrieval",
                    "Internal service interaction"
                ],
                estimated_time="30min"
            ))
        
        # Exposed secrets path
        if state.js.secrets_found > 0:
            paths.append(AttackPath(
                name="Secret Exploitation",
                steps=[
                    "1. Extract all secrets from JS analysis",
                    "2. Identify secret type (API key, token, etc.)",
                    "3. Test each secret for validity",
                    "4. Determine access level/scope",
                    "5. Document for report"
                ],
                tools=["trufflehog", "gitleaks", "manual testing"],
                success_indicators=[
                    "Valid API key access",
                    "Token with elevated privileges",
                    "Database access"
                ],
                estimated_time="15-30min"
            ))
        
        # Admin panel path
        if state.vuln_hints.admin_panel:
            paths.append(AttackPath(
                name="Admin Panel Exploitation",
                steps=[
                    "1. Identify admin panel URL",
                    "2. Test default credentials",
                    "3. Test for auth bypass",
                    "4. Test 403 bypass techniques",
                    "5. If authenticated, test for privilege escalation"
                ],
                tools=["byp4xx", "Burp Suite", "ffuf"],
                success_indicators=[
                    "Admin panel access",
                    "Bypass 403/401"
                ],
                estimated_time="30min - 1 hour"
            ))
        
        # Git exposure path
        if state.vuln_hints.git_exposed:
            paths.append(AttackPath(
                name="Git Repository Extraction",
                steps=[
                    "1. Verify /.git/config accessible",
                    "2. Run git-dumper",
                    "3. Reconstruct repository",
                    "4. Search for secrets in history",
                    "5. Analyze source code"
                ],
                tools=["git-dumper", "trufflehog"],
                success_indicators=[
                    "Full source code access",
                    "Secrets in commit history",
                    "Internal documentation"
                ],
                estimated_time="15min"
            ))
        
        return paths
    
    def _identify_quick_wins(self, state: TargetState) -> List[str]:
        """Identify quick win opportunities"""
        quick_wins = []
        
        if state.vuln_hints.git_exposed:
            quick_wins.append("🎯 .git exposed - Run git-dumper NOW")
        
        if state.vuln_hints.env_exposed:
            quick_wins.append("🎯 .env exposed - Download immediately")
        
        if state.js.secrets_found > 0:
            quick_wins.append(f"🔑 {state.js.secrets_found} secrets in JS - Validate each")
        
        if state.api.has_graphql_introspection:
            quick_wins.append("📊 GraphQL introspection enabled - Extract full schema")
        
        if state.vuln_hints.debug_mode:
            quick_wins.append("🐛 Debug mode enabled - Look for verbose errors")
        
        if state.vuln_hints.cors_misconfigured:
            quick_wins.append("🔓 CORS misconfigured - Test credential theft")
        
        if state.js.source_maps:
            quick_wins.append("📜 Source maps available - Reconstruct source code")
        
        if state.api.has_swagger:
            quick_wins.append("📖 Swagger exposed - Import to Burp")
        
        return quick_wins
    
    def generate_top_targets_report(self, limit: int = 20) -> str:
        """Generate Top N targets report"""
        states = self.state_manager.get_by_priority(min_score=0)[:limit]
        
        lines = [
            "╔══════════════════════════════════════════════════════════════════════╗",
            "║               SHADOW v6 - TOP TARGETS INTELLIGENCE                   ║",
            "╠══════════════════════════════════════════════════════════════════════╣",
            f"║  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}                                        ║",
            f"║  Total Targets: {len(states)}                                                    ║",
            "╚══════════════════════════════════════════════════════════════════════╝",
            "",
        ]
        
        for i, state in enumerate(states, 1):
            report = self.generate_target_report(state)
            
            # Priority color indicator
            priority_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢"
            }.get(report.priority, "⚪")
            
            lines.append(f"{'═' * 70}")
            lines.append(f"#{i} {priority_icon} {report.domain}")
            lines.append(f"   Score: {report.score} | Priority: {report.priority.upper()}")
            lines.append(f"{'─' * 70}")
            
            # Why interesting
            if report.why_interesting:
                lines.append("   📌 WHY INTERESTING:")
                for reason in report.why_interesting[:3]:
                    lines.append(f"      • {reason}")
            
            # Quick wins
            if report.quick_wins:
                lines.append("")
                lines.append("   ⚡ QUICK WINS:")
                for win in report.quick_wins[:3]:
                    lines.append(f"      {win}")
            
            # Attack paths
            if report.attack_paths:
                lines.append("")
                lines.append("   🎯 ATTACK PATHS:")
                for path in report.attack_paths[:2]:
                    lines.append(f"      → {path.name} ({path.estimated_time})")
            
            lines.append("")
        
        # Summary section
        lines.append("=" * 70)
        lines.append("                           SUMMARY                                   ")
        lines.append("=" * 70)
        
        critical = len([s for s in states if s.priority == "critical"])
        high = len([s for s in states if s.priority == "high"])
        medium = len([s for s in states if s.priority == "medium"])
        
        lines.append(f"🔴 Critical: {critical}")
        lines.append(f"🟠 High: {high}")
        lines.append(f"🟡 Medium: {medium}")
        lines.append("")
        
        # Time estimate
        total_hours = critical * 4 + high * 2 + medium * 1
        lines.append(f"⏱️  Estimated manual testing time: {total_hours} hours")
        lines.append("")
        lines.append("Recommendation: Focus on CRITICAL and HIGH priority targets first.")
        
        return "\n".join(lines)
    
    def generate_json_report(self, limit: int = 20) -> Dict[str, Any]:
        """Generate machine-readable JSON report"""
        states = self.state_manager.get_by_priority(min_score=0)[:limit]
        
        targets = []
        for state in states:
            report = self.generate_target_report(state)
            targets.append({
                "domain": report.domain,
                "score": report.score,
                "priority": report.priority,
                "why_interesting": report.why_interesting,
                "attack_surface": report.attack_surface,
                "quick_wins": report.quick_wins,
                "attack_paths": [
                    {
                        "name": p.name,
                        "steps": p.steps,
                        "tools": p.tools,
                        "estimated_time": p.estimated_time
                    }
                    for p in report.attack_paths
                ]
            })
        
        return {
            "generated": datetime.now().isoformat(),
            "total_targets": len(targets),
            "summary": {
                "critical": len([t for t in targets if t["priority"] == "critical"]),
                "high": len([t for t in targets if t["priority"] == "high"]),
                "medium": len([t for t in targets if t["priority"] == "medium"]),
                "low": len([t for t in targets if t["priority"] == "low"]),
            },
            "targets": targets
        }
    
    def save_reports(self, limit: int = 20):
        """Save all report formats"""
        # Text report
        text_report = self.generate_top_targets_report(limit)
        with open(self.output_dir / "TOP_TARGETS.txt", "w") as f:
            f.write(text_report)
        
        # JSON report
        json_report = self.generate_json_report(limit)
        with open(self.output_dir / "targets.json", "w") as f:
            json.dump(json_report, f, indent=2)
        
        # Markdown report
        md_report = self._generate_markdown_report(limit)
        with open(self.output_dir / "TARGETS.md", "w") as f:
            f.write(md_report)
        
        return {
            "text": self.output_dir / "TOP_TARGETS.txt",
            "json": self.output_dir / "targets.json",
            "markdown": self.output_dir / "TARGETS.md"
        }
    
    def _generate_markdown_report(self, limit: int = 20) -> str:
        """Generate Markdown report for documentation"""
        states = self.state_manager.get_by_priority(min_score=0)[:limit]
        
        lines = [
            "# SHADOW v6 - Target Intelligence Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"**Total Targets:** {len(states)}",
            "",
            "## Summary",
            "",
            "| Priority | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {len([s for s in states if s.priority == 'critical'])} |",
            f"| 🟠 High | {len([s for s in states if s.priority == 'high'])} |",
            f"| 🟡 Medium | {len([s for s in states if s.priority == 'medium'])} |",
            f"| 🟢 Low | {len([s for s in states if s.priority == 'low'])} |",
            "",
            "---",
            "",
            "## Top Targets",
            "",
        ]
        
        for i, state in enumerate(states, 1):
            report = self.generate_target_report(state)
            
            lines.append(f"### {i}. {report.domain}")
            lines.append("")
            lines.append(f"**Score:** {report.score} | **Priority:** {report.priority.upper()}")
            lines.append("")
            
            if report.why_interesting:
                lines.append("#### Why Interesting")
                for reason in report.why_interesting:
                    lines.append(f"- {reason}")
                lines.append("")
            
            if report.quick_wins:
                lines.append("#### Quick Wins")
                for win in report.quick_wins:
                    lines.append(f"- {win}")
                lines.append("")
            
            if report.attack_paths:
                lines.append("#### Attack Paths")
                for path in report.attack_paths[:3]:
                    lines.append(f"**{path.name}** ({path.estimated_time})")
                    for step in path.steps:
                        lines.append(f"  {step}")
                    lines.append("")
            
            lines.append("---")
            lines.append("")
        
        return "\n".join(lines)

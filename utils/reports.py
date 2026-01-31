#!/usr/bin/env python3
"""
SHADOW - Report Generation

Generate decision-ready outputs in various formats.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT SCHEMAS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TargetReport:
    """Single target in the report"""
    domain: str
    url: str
    score: int
    priority: str  # critical, high, medium, low, noise
    title: str
    technology: str
    params: Dict[str, str]
    tags: List[str]
    reasons: List[str]
    recommended_action: str
    findings: List[str]
    finding_count: int


@dataclass
class SummaryReport:
    """Complete scan summary report"""
    target: str
    scan_time: str
    duration_seconds: int
    stats: Dict[str, int]
    top_targets: List[TargetReport]
    critical_findings: List[Dict]
    recommendations: List[str]


# ═══════════════════════════════════════════════════════════════════════════════
# ACTION RECOMMENDATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def get_recommended_action(target: Dict) -> str:
    """
    Determine recommended action based on target characteristics.
    
    Returns action like: deep-scan, xss-test, sqli-test, manual-review, ignore
    """
    score = target.get('score', 0)
    tags = set(target.get('tags', []))
    findings = target.get('findings', [])
    
    # If already has findings, prioritize exploitation
    if findings:
        severity_map = {
            'critical': 'exploit-verify',
            'high': 'exploit-verify',
            'medium': 'deep-scan',
        }
        for sev in ['critical', 'high', 'medium']:
            if any(sev in f.lower() for f in findings):
                return severity_map.get(sev, 'manual-review')
    
    # Based on vulnerability tags
    if 'rce' in tags:
        return 'rce-test'
    if 'sqli' in tags:
        return 'sqli-test'
    if 'lfi' in tags:
        return 'lfi-test'
    if 'ssrf' in tags:
        return 'ssrf-test'
    if 'xss' in tags:
        return 'xss-test'
    if 'idor' in tags:
        return 'idor-test'
    if 'auth' in tags:
        return 'auth-bypass-test'
    if 'admin' in tags:
        return 'admin-access-test'
    if 'exposure' in tags:
        return 'info-leak-check'
    if 'graphql' in tags:
        return 'graphql-introspection'
    if 'api' in tags:
        return 'api-fuzz'
    
    # Based on score
    if score >= 10:
        return 'deep-scan'
    if score >= 7:
        return 'targeted-scan'
    if score >= 4:
        return 'light-scan'
    if score > 0:
        return 'monitor'
    
    return 'ignore'


def get_priority_label(score: int) -> str:
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


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generate various report formats"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.reports_dir = self.output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_targets_ranked(
        self, 
        targets: List[Dict],
        top_n: int = 50
    ) -> str:
        """
        Generate targets_ranked.json with actionable items.
        
        Returns path to generated file.
        """
        ranked = []
        
        for target in sorted(targets, key=lambda x: -x.get('score', 0))[:top_n]:
            ranked.append({
                'domain': target.get('domain', ''),
                'url': target.get('url', ''),
                'score': target.get('score', 0),
                'priority': get_priority_label(target.get('score', 0)),
                'title': target.get('title', ''),
                'technology': target.get('technology', ''),
                'params': target.get('params', {}),
                'tags': target.get('tags', []),
                'recommended_action': get_recommended_action(target),
                'findings': target.get('findings', []),
                'finding_count': target.get('finding_count', 0),
            })
        
        output_path = self.reports_dir / "targets_ranked.json"
        
        with open(output_path, 'w') as f:
            json.dump({
                'generated_at': datetime.utcnow().isoformat(),
                'count': len(ranked),
                'targets': ranked
            }, f, indent=2)
        
        return str(output_path)
    
    def generate_summary(
        self,
        domain: str,
        stats: Dict[str, int],
        targets: List[Dict],
        findings: List[Dict],
        duration: int = 0
    ) -> str:
        """
        Generate summary.json with complete scan overview.
        
        Returns path to generated file.
        """
        # Build recommendations based on findings
        recommendations = self._build_recommendations(targets, findings)
        
        # Build critical findings list
        critical_findings = [
            f for f in findings 
            if f.get('severity') in ('critical', 'high')
        ][:10]
        
        summary = {
            'target': domain,
            'scan_time': datetime.utcnow().isoformat(),
            'duration_seconds': duration,
            'stats': stats,
            'top_targets': [
                {
                    'url': t.get('url'),
                    'score': t.get('score'),
                    'priority': get_priority_label(t.get('score', 0)),
                    'action': get_recommended_action(t),
                    'tags': t.get('tags', [])[:5],
                }
                for t in sorted(targets, key=lambda x: -x.get('score', 0))[:10]
            ],
            'critical_findings': critical_findings,
            'recommendations': recommendations,
        }
        
        output_path = self.reports_dir / "summary.json"
        
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return str(output_path)
    
    def generate_notes(
        self,
        domain: str,
        targets: List[Dict],
        findings: List[Dict]
    ) -> str:
        """
        Generate notes.md with human-readable analysis.
        
        Returns path to generated file.
        """
        lines = [
            f"# SHADOW Scan Notes: {domain}",
            f"",
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"",
            "---",
            "",
        ]
        
        # Top targets section
        lines.append("## 🎯 Top 10 Priority Targets")
        lines.append("")
        
        top_targets = sorted(targets, key=lambda x: -x.get('score', 0))[:10]
        
        for i, target in enumerate(top_targets, 1):
            priority = get_priority_label(target.get('score', 0))
            icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(priority, '⚪')
            
            lines.append(f"### {i}. {icon} [{priority.upper()}] Score: {target.get('score', 0)}")
            lines.append(f"")
            lines.append(f"**URL:** `{target.get('url', 'N/A')}`")
            
            if target.get('technology'):
                lines.append(f"**Tech:** {target.get('technology')}")
            
            if target.get('tags'):
                lines.append(f"**Tags:** {', '.join(target.get('tags', [])[:5])}")
            
            action = get_recommended_action(target)
            lines.append(f"**Recommended:** {action}")
            lines.append(f"")
            
            # Why this target is interesting
            lines.append("**Why interesting:**")
            if target.get('tags'):
                for tag in target.get('tags', [])[:3]:
                    reason = self._get_tag_reason(tag)
                    lines.append(f"- {reason}")
            lines.append("")
        
        # Findings section
        if findings:
            lines.append("---")
            lines.append("")
            lines.append("## 🔒 Confirmed Findings")
            lines.append("")
            
            for finding in findings[:20]:
                sev = finding.get('severity', 'info')
                icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡'}.get(sev, '🔵')
                lines.append(f"- {icon} **[{sev.upper()}]** {finding.get('title', finding.get('finding_type', 'Unknown'))}")
            lines.append("")
        
        # Next steps
        lines.append("---")
        lines.append("")
        lines.append("## 📋 Next Steps")
        lines.append("")
        
        recommendations = self._build_recommendations(targets, findings)
        for rec in recommendations:
            lines.append(f"- {rec}")
        
        lines.append("")
        lines.append("---")
        lines.append(f"*Generated by SHADOW v2.3*")
        
        output_path = self.reports_dir / "notes.md"
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        
        return str(output_path)
    
    def generate_jsonl(
        self,
        targets: List[Dict],
        filename: str = "targets.jsonl"
    ) -> str:
        """
        Generate JSONL output for tool integration.
        
        Returns path to generated file.
        """
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            for target in targets:
                f.write(json.dumps(target) + '\n')
        
        return str(output_path)
    
    def _build_recommendations(
        self, 
        targets: List[Dict], 
        findings: List[Dict]
    ) -> List[str]:
        """Build list of recommendations based on scan results"""
        recs = []
        
        # Check for critical findings
        critical = [f for f in findings if f.get('severity') == 'critical']
        high = [f for f in findings if f.get('severity') == 'high']
        
        if critical:
            recs.append(f"🚨 IMMEDIATE: {len(critical)} critical findings require immediate attention")
        
        if high:
            recs.append(f"⚠️ HIGH PRIORITY: Review {len(high)} high-severity findings")
        
        # Check for common vulnerability patterns
        all_tags = []
        for t in targets:
            all_tags.extend(t.get('tags', []))
        
        tag_counts = {}
        for tag in all_tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        if tag_counts.get('rce', 0) > 0:
            recs.append("🔴 RCE candidates found - prioritize command injection testing")
        
        if tag_counts.get('sqli', 0) > 3:
            recs.append(f"🔴 {tag_counts['sqli']} SQLi candidates - run automated SQLi scanning")
        
        if tag_counts.get('ssrf', 0) > 3:
            recs.append(f"🟠 {tag_counts['ssrf']} SSRF candidates - test with Collaborator/webhook")
        
        if tag_counts.get('idor', 0) > 5:
            recs.append(f"🟠 {tag_counts['idor']} IDOR candidates - test ID enumeration")
        
        if tag_counts.get('admin', 0) > 0:
            recs.append("🟡 Admin panels found - check for auth bypass")
        
        if tag_counts.get('graphql', 0) > 0:
            recs.append("🟡 GraphQL endpoints - test introspection and batching")
        
        if tag_counts.get('exposure', 0) > 3:
            recs.append("🟡 Multiple exposure indicators - check for sensitive data leaks")
        
        if not recs:
            recs.append("No high-priority issues found - continue with broader scanning")
        
        return recs
    
    def _get_tag_reason(self, tag: str) -> str:
        """Get human-readable reason for a tag"""
        reasons = {
            'rce': 'Command execution parameters detected',
            'sqli': 'SQL injection candidate parameters',
            'xss': 'XSS-prone input parameters',
            'ssrf': 'Server-side request forgery indicators',
            'lfi': 'Local file inclusion parameters',
            'idor': 'Insecure direct object reference (ID parameters)',
            'redirect': 'Open redirect parameters',
            'admin': 'Administrative interface',
            'api': 'API endpoint',
            'graphql': 'GraphQL endpoint (check introspection)',
            'auth': 'Authentication-related endpoint',
            'exposure': 'Potential information exposure',
            'debug': 'Debug/development endpoint',
            'upload': 'File upload functionality',
            'internal': 'Internal/staging endpoint',
        }
        return reasons.get(tag, f'Tagged as: {tag}')

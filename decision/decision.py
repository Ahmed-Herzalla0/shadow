#!/usr/bin/env python3
"""
SHADOW Decision Engine - Scoring and Action Recommendation

This module implements a configurable scoring algorithm with tunable weights,
heuristics for vulnerability prioritization, and action suggestions based on
discovered endpoints and parameters.

Chosen Features & Default Weights:
- XSS Parameters (search, query, q, etc.): Weight 2.0x for XSS scope
- SSRF/Redirect Parameters (url, redirect, callback): Weight 3.0x
- RCE Parameters (cmd, exec): Weight 5.0x (highest priority)
- Path Patterns (/admin, /api, /graphql): Weight 1.5x
- Technology Bonuses (Spring, PHP): Weight 1.2x
- Noise Penalties (static files, CDN): Weight -2.0x

The weights can be customized via environment variables or a weights.json file.

Author: SHADOW Team
License: MIT
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# WEIGHTS CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_WEIGHTS = {
    # Category multipliers
    "multipliers": {
        "xss": 2.0,
        "ssrf": 3.0,
        "lfi": 3.5,
        "rce": 5.0,
        "idor": 2.5,
        "sqli": 3.0,
        "auth": 2.0,
        "exposure": 1.5,
        "admin": 2.0,
        "api": 1.5,
        "graphql": 2.0,
    },

    # Parameter scores (base score before multiplier)
    "params": {
        # XSS candidates
        "search": 2, "query": 2, "q": 2, "name": 2, "message": 2,
        "comment": 2, "body": 2, "content": 2, "title": 2, "error": 2,

        # SSRF/Redirect
        "url": 4, "redirect": 4, "next": 3, "return": 3, "goto": 3,
        "dest": 3, "target": 3, "uri": 3, "callback": 3, "webhook": 4,

        # LFI
        "file": 4, "filename": 4, "filepath": 5, "path": 3,
        "include": 5, "template": 4, "document": 3, "page": 3,

        # RCE
        "cmd": 5, "exec": 5, "command": 5, "execute": 5, "ping": 4, "host": 3,

        # IDOR
        "id": 3, "user_id": 4, "account_id": 4, "order_id": 3, "doc_id": 3,

        # SQLi
        "sort": 3, "order": 3, "orderby": 3, "filter": 3, "where": 4, "column": 3,

        # Auth
        "token": 3, "api_key": 3, "auth": 2, "password": 3, "secret": 4,
    },

    # Path pattern scores
    "paths": {
        r"/api/": 3, r"/v\d+/": 2, r"/internal/": 4, r"/admin": 4,
        r"/dashboard": 3, r"/config": 4, r"/debug": 5, r"/graphql": 4,
        r"/upload": 3, r"/webhook": 3, r"/proxy": 4, r"/actuator": 5,
        r"/swagger": 4, r"\.git": 5, r"\.env": 5, r"/console": 4,
    },

    # Technology bonuses
    "technology": {
        "php": 2, "spring": 3, "struts": 4, "wordpress": 3,
        "jenkins": 4, "confluence": 4, "graphql": 3, "java": 2,
    },

    # Noise penalties (negative scores)
    "noise": {
        r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff)$": -5,
        r"/(static|assets|images|css|fonts)/": -3,
        r"cloudfront|cloudflare|akamai|fastly": -4,
        r"(404|not\s*found)": -2,
    },

    # Priority thresholds
    "thresholds": {
        "critical": 15,
        "high": 10,
        "medium": 5,
        "low": 1,
    },
}


def load_weights(weights_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Load weights from file or environment, falling back to defaults.
    
    Priority:
    1. Environment variable SHADOW_WEIGHTS_FILE
    2. Provided weights_file parameter
    3. weights.json in current directory
    4. Default weights
    """
    weights_path = None

    # Check environment variable
    env_path = os.environ.get("SHADOW_WEIGHTS_FILE")
    if env_path and Path(env_path).exists():
        weights_path = Path(env_path)

    # Check parameter
    elif weights_file and Path(weights_file).exists():
        weights_path = Path(weights_file)

    # Check current directory
    elif Path("weights.json").exists():
        weights_path = Path("weights.json")

    if weights_path:
        try:
            with open(weights_path) as f:
                custom = json.load(f)
            # Merge with defaults
            merged = DEFAULT_WEIGHTS.copy()
            for key, value in custom.items():
                if key in merged and isinstance(merged[key], dict):
                    merged[key].update(value)
                else:
                    merged[key] = value
            return merged
        except (OSError, json.JSONDecodeError):
            pass

    return DEFAULT_WEIGHTS


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScoredTarget:
    """A scored and ranked target endpoint"""
    url: str
    domain: str
    path: str
    params: Dict[str, str]
    score: int
    priority: str  # critical, high, medium, low, noise
    action: str  # recommended action
    reasons: List[str]
    tags: List[str]
    source: str = ""  # which module discovered this

    def __lt__(self, other: ScoredTarget) -> bool:
        """Sort by score descending"""
        return self.score > other.score


@dataclass
class HeuristicResult:
    """Result of applying heuristics"""
    score_adjustment: int
    reasons: List[str]
    tags: List[str]


# ═══════════════════════════════════════════════════════════════════════════════
# DECISION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class DecisionEngine:
    """
    Decision engine for scoring and ranking targets.
    
    Usage:
        engine = DecisionEngine()
        scored = engine.score_targets(jsonl_data)
        for target in scored[:10]:
            print(f"{target.url}: {target.score} ({target.action})")
    """

    def __init__(self, weights_file: Optional[str] = None):
        self.weights = load_weights(weights_file)
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    def score_targets(self, targets: List[Dict[str, Any]]) -> List[ScoredTarget]:
        """
        Score and rank a list of targets.
        
        Args:
            targets: List of target dictionaries from JSONL
        
        Returns:
            Sorted list of ScoredTarget objects (highest score first)
        """
        scored = []

        for target in targets:
            try:
                scored_target = self._score_single(target)
                scored.append(scored_target)
            except Exception:
                # Skip malformed targets
                continue

        # Sort by score descending
        scored.sort()

        return scored

    def _score_single(self, target: Dict[str, Any]) -> ScoredTarget:
        """Score a single target"""
        url = target.get("url", "")
        domain = target.get("domain", self._extract_domain(url))
        path = target.get("path", self._extract_path(url))
        params = target.get("params", {})
        technology = target.get("technology", "")
        source = target.get("source", "unknown")

        if isinstance(params, str):
            params = self._parse_params(params)

        total_score = 0
        reasons = []
        tags = set()

        # Score parameters
        param_score, param_reasons, param_tags = self._score_params(params)
        total_score += param_score
        reasons.extend(param_reasons)
        tags.update(param_tags)

        # Score path patterns
        path_score, path_reasons, path_tags = self._score_path(path)
        total_score += path_score
        reasons.extend(path_reasons)
        tags.update(path_tags)

        # Score technology
        tech_score, tech_reasons, tech_tags = self._score_technology(technology)
        total_score += tech_score
        reasons.extend(tech_reasons)
        tags.update(tech_tags)

        # Apply noise penalties
        noise_score, noise_reasons, noise_tags = self._apply_noise(url, path)
        total_score += noise_score
        reasons.extend(noise_reasons)
        tags.update(noise_tags)

        # Apply heuristics
        heuristic = self._apply_heuristics(tags, params, path)
        total_score += heuristic.score_adjustment
        reasons.extend(heuristic.reasons)
        tags.update(heuristic.tags)

        # Minimum score is 0
        total_score = max(0, total_score)

        # Determine priority
        priority = self._get_priority(total_score)

        # Determine recommended action
        action = self._get_action(total_score, tags)

        return ScoredTarget(
            url=url,
            domain=domain,
            path=path,
            params=params,
            score=total_score,
            priority=priority,
            action=action,
            reasons=reasons,
            tags=list(tags),
            source=source,
        )

    def _score_params(self, params: Dict[str, str]) -> Tuple[int, List[str], set]:
        """Score based on parameter names"""
        score = 0
        reasons = []
        tags = set()

        param_weights = self.weights.get("params", {})
        multipliers = self.weights.get("multipliers", {})

        for param_name in params.keys():
            param_lower = param_name.lower()

            if param_lower in param_weights:
                base_score = param_weights[param_lower]

                # Determine category and apply multiplier
                category = self._get_param_category(param_lower)
                multiplier = multipliers.get(category, 1.0)

                final_score = int(base_score * multiplier)
                score += final_score
                reasons.append(f"+{final_score}: {category.upper()} param ({param_name})")
                tags.add(category)

        return score, reasons, tags

    def _score_path(self, path: str) -> Tuple[int, List[str], set]:
        """Score based on path patterns"""
        score = 0
        reasons = []
        tags = set()

        path_patterns = self.weights.get("paths", {})
        path_lower = path.lower()

        for pattern, base_score in path_patterns.items():
            if self._match_pattern(pattern, path_lower):
                score += base_score
                tag = self._get_path_tag(pattern)
                reasons.append(f"+{base_score}: {tag.upper()} path pattern")
                tags.add(tag)

        return score, reasons, tags

    def _score_technology(self, technology: str) -> Tuple[int, List[str], set]:
        """Score based on detected technology"""
        score = 0
        reasons = []
        tags = set()

        tech_weights = self.weights.get("technology", {})
        tech_lower = technology.lower()

        for tech, bonus in tech_weights.items():
            if tech in tech_lower:
                score += bonus
                reasons.append(f"+{bonus}: {tech.upper()} detected")
                tags.add(tech)

        return score, reasons, tags

    def _apply_noise(self, url: str, path: str) -> Tuple[int, List[str], set]:
        """Apply noise penalties"""
        score = 0
        reasons = []
        tags = set()

        noise_patterns = self.weights.get("noise", {})
        context = f"{url} {path}".lower()

        for pattern, penalty in noise_patterns.items():
            if self._match_pattern(pattern, context):
                score += penalty  # penalty is already negative
                reasons.append(f"{penalty}: Noise pattern matched")
                tags.add("noise")

        return score, reasons, tags

    def _apply_heuristics(
        self,
        tags: set,
        params: Dict[str, str],
        path: str,
    ) -> HeuristicResult:
        """Apply additional heuristics for edge cases"""
        score_adj = 0
        reasons = []
        new_tags = set()

        # Heuristic 1: Multiple vulnerability types = higher interest
        vuln_tags = {"xss", "ssrf", "lfi", "rce", "sqli", "idor"}
        found_vulns = tags & vuln_tags
        if len(found_vulns) >= 2:
            bonus = len(found_vulns) * 2
            score_adj += bonus
            reasons.append(f"+{bonus}: Multiple vuln indicators ({', '.join(found_vulns)})")
            new_tags.add("multi-vuln")

        # Heuristic 2: Debug/admin paths with params = high priority
        if "debug" in tags or "admin" in tags:
            if params:
                score_adj += 3
                reasons.append("+3: Admin/debug path with parameters")
                new_tags.add("high-value")

        # Heuristic 3: API endpoints with IDOR params
        if "api" in tags and "idor" in tags:
            score_adj += 2
            reasons.append("+2: API endpoint with IDOR candidate")
            new_tags.add("api-idor")

        # Heuristic 4: GraphQL endpoints are always interesting
        if "graphql" in tags:
            score_adj += 2
            reasons.append("+2: GraphQL introspection candidate")

        return HeuristicResult(
            score_adjustment=score_adj,
            reasons=reasons,
            tags=new_tags,
        )

    def _get_priority(self, score: int) -> str:
        """Convert score to priority label"""
        thresholds = self.weights.get("thresholds", {})

        if score >= thresholds.get("critical", 15):
            return "critical"
        elif score >= thresholds.get("high", 10):
            return "high"
        elif score >= thresholds.get("medium", 5):
            return "medium"
        elif score >= thresholds.get("low", 1):
            return "low"
        return "noise"

    def _get_action(self, score: int, tags: set) -> str:
        """Determine recommended action based on score and tags"""
        # Priority-based actions for specific vuln types
        if "rce" in tags:
            return "rce-verify"
        if "sqli" in tags:
            return "sqli-test"
        if "lfi" in tags:
            return "lfi-test"
        if "ssrf" in tags:
            return "ssrf-test"
        if "xss" in tags:
            return "xss-test"
        if "idor" in tags:
            return "idor-test"
        if "graphql" in tags:
            return "graphql-introspect"
        if "admin" in tags:
            return "admin-access-check"
        if "exposure" in tags:
            return "info-leak-verify"

        # Score-based fallback
        if score >= 15:
            return "manual-review"
        elif score >= 10:
            return "deep-scan"
        elif score >= 5:
            return "targeted-scan"
        elif score >= 1:
            return "monitor"
        return "ignore"

    def _get_param_category(self, param: str) -> str:
        """Determine vulnerability category for a parameter"""
        xss_params = {"search", "query", "q", "name", "message", "comment", "body", "content", "title", "error"}
        ssrf_params = {"url", "redirect", "next", "return", "goto", "dest", "target", "uri", "callback", "webhook"}
        lfi_params = {"file", "filename", "filepath", "path", "include", "template", "document", "page"}
        rce_params = {"cmd", "exec", "command", "execute", "ping", "host"}
        idor_params = {"id", "user_id", "account_id", "order_id", "doc_id", "file_id"}
        sqli_params = {"sort", "order", "orderby", "filter", "where", "column", "table"}
        auth_params = {"token", "api_key", "auth", "password", "secret"}

        if param in xss_params:
            return "xss"
        if param in ssrf_params:
            return "ssrf"
        if param in lfi_params:
            return "lfi"
        if param in rce_params:
            return "rce"
        if param in idor_params:
            return "idor"
        if param in sqli_params:
            return "sqli"
        if param in auth_params:
            return "auth"
        return "unknown"

    def _get_path_tag(self, pattern: str) -> str:
        """Get tag for a path pattern"""
        if "api" in pattern or r"/v\d" in pattern:
            return "api"
        if "admin" in pattern or "dashboard" in pattern:
            return "admin"
        if "debug" in pattern or "console" in pattern:
            return "debug"
        if "graphql" in pattern:
            return "graphql"
        if "actuator" in pattern or "swagger" in pattern:
            return "exposure"
        if ".git" in pattern or ".env" in pattern:
            return "exposure"
        if "upload" in pattern:
            return "upload"
        if "proxy" in pattern or "webhook" in pattern:
            return "ssrf"
        return "interesting"

    def _match_pattern(self, pattern: str, text: str) -> bool:
        """Match a regex pattern against text, caching compiled patterns"""
        if pattern not in self._compiled_patterns:
            try:
                self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                return False

        return bool(self._compiled_patterns[pattern].search(text))

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or url.split("/")[0]
        except Exception:
            return ""

    def _extract_path(self, url: str) -> str:
        """Extract path from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.path or "/"
        except Exception:
            return "/"

    def _parse_params(self, params_str: str) -> Dict[str, str]:
        """Parse params from string format"""
        if not params_str:
            return {}

        try:
            # Try JSON first
            return json.loads(params_str)
        except json.JSONDecodeError:
            pass

        # Try query string format
        try:
            from urllib.parse import parse_qs
            parsed = parse_qs(params_str)
            return {k: v[0] if v else "" for k, v in parsed.items()}
        except Exception:
            return {}


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def score_single_target(
    url: str,
    params: Optional[Dict[str, str]] = None,
    technology: str = "",
    weights_file: Optional[str] = None,
) -> ScoredTarget:
    """
    Convenience function to score a single target.
    
    Usage:
        result = score_single_target(
            "https://example.com/api/users",
            params={"id": "1"},
        )
        print(f"Score: {result.score}, Action: {result.action}")
    """
    engine = DecisionEngine(weights_file)

    target = {
        "url": url,
        "params": params or {},
        "technology": technology,
    }

    return engine._score_single(target)


def get_priority_label(score: int) -> str:
    """Get priority label for a score"""
    return DecisionEngine()._get_priority(score)


def get_action_suggestion(score: int, tags: List[str]) -> str:
    """Get action suggestion for score and tags"""
    return DecisionEngine()._get_action(score, set(tags))

#!/usr/bin/env python3
"""
SHADOW - Decision Engine Tests

Tests for scoring, prioritization, and action suggestions.
Uses the new DecisionEngine from decision/decision.py
"""

import pytest

from decision.decision import (
    DEFAULT_WEIGHTS,
    DecisionEngine,
    HeuristicResult,
    ScoredTarget,
    load_weights,
)


class TestDecisionEngine:
    """Tests for the DecisionEngine class"""

    def test_score_targets_basic(self, scorer):
        """Test basic target scoring"""
        targets = [
            {"url": "https://api.example.com/users", "path": "/api/v1/users", "params": {"id": "1"}},
        ]

        results = scorer.score_targets(targets)

        assert len(results) == 1
        result = results[0]
        assert isinstance(result, ScoredTarget)
        assert result.score >= 3  # id param + /api/ path
        assert 'idor' in result.tags or 'api' in result.tags
        assert len(result.reasons) > 0

    def test_score_targets_ssrf_candidates(self, scorer):
        """Test SSRF-related parameter scoring"""
        ssrf_params = ['url', 'redirect', 'callback', 'webhook', 'dest', 'target']

        for param in ssrf_params:
            targets = [{"url": f"https://example.com/fetch?{param}=http://evil.com", 
                       "path": "/fetch", "params": {param: "http://evil.com"}}]
            results = scorer.score_targets(targets)
            
            assert len(results) == 1
            assert results[0].score >= 3, f"SSRF param '{param}' should score >= 3"
            assert any(t in results[0].tags for t in ['ssrf', 'redirect']), \
                f"SSRF param '{param}' should have ssrf/redirect tag"

    def test_score_targets_rce_candidates(self, scorer):
        """Test RCE-related parameter scoring"""
        rce_params = ['cmd', 'exec', 'command', 'execute']

        for param in rce_params:
            targets = [{"url": f"https://example.com/run?{param}=ls",
                       "path": "/run", "params": {param: "ls"}}]
            results = scorer.score_targets(targets)
            
            assert len(results) == 1
            assert results[0].score >= 5, f"RCE param '{param}' should score >= 5"
            assert 'rce' in results[0].tags

    def test_score_targets_lfi_candidates(self, scorer):
        """Test LFI-related parameter scoring"""
        lfi_params = ['file', 'filename', 'filepath', 'include', 'template']

        for param in lfi_params:
            targets = [{"url": f"https://example.com/read?{param}=../etc/passwd",
                       "path": "/read", "params": {param: "../etc/passwd"}}]
            results = scorer.score_targets(targets)
            
            assert len(results) == 1
            assert results[0].score >= 3, f"LFI param '{param}' should score >= 3"
            assert 'lfi' in results[0].tags

    def test_score_targets_admin_path(self, scorer):
        """Test admin path scoring"""
        targets = [{"url": "https://example.com/admin/dashboard", 
                   "path": "/admin/dashboard", "params": {}}]
        results = scorer.score_targets(targets)

        assert len(results) == 1
        assert results[0].score >= 4  # /admin pattern
        assert 'admin' in results[0].tags

    def test_score_targets_debug_exposure(self, scorer):
        """Test debug endpoint scoring"""
        targets = [{"url": "https://example.com/debug/console?cmd=ls",
                   "path": "/debug/console", "params": {"cmd": "ls"}}]
        results = scorer.score_targets(targets)

        assert len(results) == 1
        assert results[0].score >= 10  # /debug = 5 + cmd = 5
        assert 'debug' in results[0].tags
        assert 'rce' in results[0].tags

    def test_score_targets_technology_bonus(self, scorer):
        """Test technology-based scoring bonus"""
        targets = [{"url": "https://example.com/api/users",
                   "path": "/api/users", "params": {}, "technology": "Spring Boot, Java"}]
        results = scorer.score_targets(targets)

        assert len(results) == 1
        assert results[0].score >= 5  # /api/ + spring/java bonus
        assert 'spring' in results[0].tags or 'java' in results[0].tags

    def test_score_targets_noise_penalty(self, scorer):
        """Test noise pattern penalties"""
        # Static file
        targets = [{"url": "https://example.com/static/app.js",
                   "path": "/static/app.js", "params": {}}]
        results = scorer.score_targets(targets)

        assert len(results) == 1
        assert results[0].score == 0  # Should be penalized to 0
        assert 'noise' in results[0].tags

    def test_score_targets_multiple_vulns_bonus(self, scorer):
        """Test bonus for multiple vulnerability indicators"""
        targets = [{"url": "https://example.com/api/fetch?url=x&file=y&id=1",
                   "path": "/api/fetch", "params": {"url": "x", "file": "y", "id": "1"}}]
        results = scorer.score_targets(targets)

        assert len(results) == 1
        # Should get bonus for multiple vuln types
        assert results[0].score >= 10
        vuln_tags = set(results[0].tags) & {'ssrf', 'lfi', 'idor'}
        assert len(vuln_tags) >= 2

    def test_score_targets_graphql(self, scorer):
        """Test GraphQL endpoint scoring"""
        targets = [{"url": "https://example.com/graphql?query=test",
                   "path": "/graphql", "params": {"query": "{ users { id } }"}}]
        results = scorer.score_targets(targets)

        assert len(results) == 1
        assert results[0].score >= 4  # /graphql = 4 points
        assert 'graphql' in results[0].tags

    def test_score_targets_actuator(self, scorer):
        """Test Spring Actuator detection"""
        targets = [{"url": "https://example.com/actuator/health",
                   "path": "/actuator/health", "params": {}}]
        results = scorer.score_targets(targets)

        assert len(results) == 1
        assert results[0].score >= 5  # /actuator = 5 points

    def test_score_targets_sorted_by_score(self, scorer):
        """Test that results are sorted by score descending"""
        targets = [
            {"url": "https://example.com/static/app.js", "path": "/static/app.js", "params": {}},  # Low
            {"url": "https://example.com/admin?cmd=ls", "path": "/admin", "params": {"cmd": "ls"}},  # High
            {"url": "https://example.com/api", "path": "/api", "params": {}},  # Medium
        ]
        results = scorer.score_targets(targets)

        assert len(results) == 3
        # Check sorted by score descending
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)


class TestPriority:
    """Tests for priority calculation in DecisionEngine"""

    def test_priority_critical(self, scorer):
        """Test critical priority assignment"""
        targets = [{"url": "https://example.com/debug/console?cmd=ls&exec=1",
                   "path": "/debug/console", "params": {"cmd": "ls", "exec": "1"}}]
        results = scorer.score_targets(targets)
        
        assert results[0].priority == "critical"

    def test_priority_high(self, scorer):
        """Test high priority assignment"""
        targets = [{"url": "https://example.com/admin",
                   "path": "/admin", "params": {"id": "1"}}]
        results = scorer.score_targets(targets)
        
        assert results[0].priority in ("critical", "high")

    def test_priority_low_or_noise(self, scorer):
        """Test low/noise priority assignment"""
        targets = [{"url": "https://example.com/about",
                   "path": "/about", "params": {}}]
        results = scorer.score_targets(targets)
        
        assert results[0].priority in ("low", "noise")


class TestActionSuggestions:
    """Tests for action suggestion generation"""

    def test_action_for_high_score(self, scorer):
        """Test action suggestion for high-scoring targets"""
        targets = [{"url": "https://example.com/debug?cmd=ls",
                   "path": "/debug", "params": {"cmd": "ls"}}]
        results = scorer.score_targets(targets)
        
        assert results[0].action != ""
        # Action can be 'rce-verify', 'manual-test', etc.
        assert any(word in results[0].action.lower() for word in ["verify", "manual", "test", "rce"])

    def test_action_for_noise(self, scorer):
        """Test action suggestion for noise targets"""
        targets = [{"url": "https://example.com/static/app.js",
                   "path": "/static/app.js", "params": {}}]
        results = scorer.score_targets(targets)
        
        assert "skip" in results[0].action.lower() or "ignore" in results[0].action.lower()


class TestWeightsConfiguration:
    """Tests for weights loading and configuration"""

    def test_load_default_weights(self):
        """Test loading default weights"""
        weights = load_weights()
        
        assert weights == DEFAULT_WEIGHTS
        assert "multipliers" in weights
        assert "params" in weights
        assert "paths" in weights

    def test_default_weights_structure(self):
        """Verify default weights structure"""
        assert "multipliers" in DEFAULT_WEIGHTS
        assert "params" in DEFAULT_WEIGHTS
        assert "paths" in DEFAULT_WEIGHTS
        assert "technology" in DEFAULT_WEIGHTS
        assert "noise" in DEFAULT_WEIGHTS
        assert "thresholds" in DEFAULT_WEIGHTS

    def test_critical_params_exist(self):
        """Verify key parameters are defined"""
        critical_params = ['id', 'url', 'file', 'cmd', 'redirect', 'search']
        for param in critical_params:
            assert param in DEFAULT_WEIGHTS["params"], f"Missing critical param: {param}"

    def test_critical_paths_exist(self):
        """Verify key path patterns are defined"""
        critical_patterns = ['/api/', '/admin', '/debug', '/graphql']
        for pattern in critical_patterns:
            assert pattern in DEFAULT_WEIGHTS["paths"], f"Missing critical path: {pattern}"

    def test_critical_techs_exist(self):
        """Verify key technologies are defined"""
        critical_techs = ['php', 'spring', 'wordpress', 'jenkins', 'graphql']
        for tech in critical_techs:
            assert tech in DEFAULT_WEIGHTS["technology"], f"Missing critical tech: {tech}"


class TestScoredTarget:
    """Tests for ScoredTarget dataclass"""

    def test_scored_target_sorting(self):
        """Test that ScoredTarget sorts by score descending"""
        t1 = ScoredTarget(
            url="https://a.com", domain="a.com", path="/", params={},
            score=10, priority="high", action="test", reasons=[], tags=[]
        )
        t2 = ScoredTarget(
            url="https://b.com", domain="b.com", path="/", params={},
            score=5, priority="medium", action="test", reasons=[], tags=[]
        )
        t3 = ScoredTarget(
            url="https://c.com", domain="c.com", path="/", params={},
            score=15, priority="critical", action="test", reasons=[], tags=[]
        )

        sorted_targets = sorted([t1, t2, t3])
        
        assert sorted_targets[0].score == 15  # Highest first
        assert sorted_targets[1].score == 10
        assert sorted_targets[2].score == 5


class TestHeuristicResult:
    """Tests for HeuristicResult dataclass"""

    def test_heuristic_result_creation(self):
        """Test HeuristicResult instantiation"""
        result = HeuristicResult(
            score_adjustment=5,
            reasons=["Multiple vulns"],
            tags=["multi-vuln"]
        )
        
        assert result.score_adjustment == 5
        assert len(result.reasons) == 1
        assert "multi-vuln" in result.tags

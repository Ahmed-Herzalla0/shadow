#!/usr/bin/env python3
"""
SHADOW - Decision Engine Tests

Tests for scoring, prioritization, and action suggestions.
"""

from core.scorer import (
    NOISE_PATTERNS,
    PARAM_SCORES,
    PATH_SCORES,
    TECH_SCORES,
    ScoreResult,
    format_target,
    get_priority,
)


class TestScorer:
    """Tests for the Scorer class"""

    def test_score_endpoint_basic(self, scorer):
        """Test basic endpoint scoring"""
        result = scorer.score_endpoint(
            path="/api/v1/users",
            params={"id": "1"}
        )

        assert isinstance(result, ScoreResult)
        assert result.total >= 3  # id param = 3 points + /api/ = 3 points
        assert 'idor' in result.tags
        assert 'api' in result.tags
        assert len(result.reasons) > 0

    def test_score_endpoint_ssrf_candidates(self, scorer):
        """Test SSRF-related parameter scoring"""
        ssrf_params = ['url', 'redirect', 'callback', 'webhook', 'dest', 'target']

        for param in ssrf_params:
            result = scorer.score_endpoint(
                path="/fetch",
                params={param: "http://example.com"}
            )
            assert result.total >= 3, f"SSRF param '{param}' should score >= 3"
            assert any(t in result.tags for t in ['ssrf', 'redirect']), \
                f"SSRF param '{param}' should have ssrf/redirect tag"

    def test_score_endpoint_rce_candidates(self, scorer):
        """Test RCE-related parameter scoring"""
        rce_params = ['cmd', 'exec', 'command', 'execute']

        for param in rce_params:
            result = scorer.score_endpoint(
                path="/run",
                params={param: "ls"}
            )
            assert result.total >= 5, f"RCE param '{param}' should score >= 5"
            assert 'rce' in result.tags

    def test_score_endpoint_lfi_candidates(self, scorer):
        """Test LFI-related parameter scoring"""
        lfi_params = ['file', 'filename', 'filepath', 'include', 'template']

        for param in lfi_params:
            result = scorer.score_endpoint(
                path="/read",
                params={param: "../etc/passwd"}
            )
            assert result.total >= 3, f"LFI param '{param}' should score >= 3"
            assert 'lfi' in result.tags

    def test_score_endpoint_admin_path(self, scorer):
        """Test admin path scoring"""
        result = scorer.score_endpoint(
            path="/admin/dashboard",
            params={}
        )

        assert result.total >= 4  # /admin = 4 points
        assert 'admin' in result.tags

    def test_score_endpoint_debug_exposure(self, scorer):
        """Test debug endpoint scoring"""
        result = scorer.score_endpoint(
            path="/debug/console",
            params={"cmd": "ls"}
        )

        assert result.total >= 10  # /debug = 5 + cmd = 5
        assert 'debug' in result.tags
        assert 'rce' in result.tags

    def test_score_endpoint_technology_bonus(self, scorer):
        """Test technology-based scoring bonus"""
        result = scorer.score_endpoint(
            path="/api/users",
            params={},
            technology="Spring Boot, Java"
        )

        assert result.total >= 5  # /api/ = 3 + spring = 3 + java = 2
        assert 'spring' in result.tags or 'java' in result.tags

    def test_score_endpoint_noise_penalty(self, scorer):
        """Test noise pattern penalties"""
        # Static file
        result = scorer.score_endpoint(
            path="/static/app.js",
            params={}
        )
        assert result.total == 0  # Should be penalized to 0
        assert 'noise' in result.tags

        # CDN domain
        result = scorer.score_endpoint(
            path="/assets/image.png",
            params={},
            title="cloudfront distribution"
        )
        assert result.total == 0

    def test_score_endpoint_multiple_vulns_bonus(self, scorer):
        """Test bonus for multiple vulnerability indicators"""
        result = scorer.score_endpoint(
            path="/api/fetch",
            params={"url": "x", "file": "y", "id": "1"}  # ssrf + lfi + idor
        )

        # Should get bonus for multiple vuln types
        assert result.total >= 10
        assert len(set(result.tags) & {'ssrf', 'lfi', 'idor'}) >= 2

    def test_score_endpoint_graphql(self, scorer):
        """Test GraphQL endpoint scoring"""
        result = scorer.score_endpoint(
            path="/graphql",
            params={"query": "{ users { id } }"}
        )

        assert result.total >= 4  # /graphql = 4 points
        assert 'graphql' in result.tags

    def test_score_endpoint_actuator(self, scorer):
        """Test Spring Actuator detection"""
        result = scorer.score_endpoint(
            path="/actuator/health",
            params={}
        )

        assert result.total >= 5  # /actuator = 5 points
        assert 'exposure' in result.tags

    def test_score_asset_internal_naming(self, scorer):
        """Test asset scoring for internal naming patterns"""
        internal_subdomains = [
            ("dev.example.com", "internal"),
            ("staging.example.com", "internal"),
            ("api.example.com", "api"),
            ("admin.example.com", "admin"),
            ("jenkins.example.com", "ci"),
            ("grafana.example.com", "monitoring"),
        ]

        for domain, expected_tag in internal_subdomains:
            result = scorer.score_asset(domain)
            assert result.total >= 2, f"{domain} should score >= 2"
            assert expected_tag in result.tags, f"{domain} should have tag '{expected_tag}'"


class TestPriority:
    """Tests for priority calculation"""

    def test_get_priority_critical(self):
        assert get_priority(10) == "critical"
        assert get_priority(15) == "critical"

    def test_get_priority_high(self):
        assert get_priority(7) == "high"
        assert get_priority(9) == "high"

    def test_get_priority_medium(self):
        assert get_priority(4) == "medium"
        assert get_priority(6) == "medium"

    def test_get_priority_low(self):
        assert get_priority(1) == "low"
        assert get_priority(3) == "low"

    def test_get_priority_noise(self):
        assert get_priority(0) == "noise"
        assert get_priority(-1) == "noise"


class TestFormatTarget:
    """Tests for target formatting"""

    def test_format_target_basic(self):
        target = {
            "url": "https://api.example.com/admin",
            "score": 10,
            "technology": "PHP",
            "title": "Admin Panel",
            "params": {"id": "1"},
            "tags": ["admin", "idor"],
        }

        output = format_target(target)

        assert "CRITICAL" in output
        assert "Score: 10" in output
        assert "https://api.example.com/admin" in output
        assert "PHP" in output
        assert "Admin Panel" in output

    def test_format_target_with_findings(self):
        target = {
            "url": "https://example.com/vuln",
            "score": 8,
            "findings": ["xss-reflected", "sqli"],
        }

        output = format_target(target)

        assert "Findings:" in output
        assert "xss-reflected" in output


class TestScoringRules:
    """Tests for scoring rule definitions"""

    def test_param_scores_exist(self):
        """Verify key parameters are defined"""
        critical_params = ['id', 'url', 'file', 'cmd', 'redirect', 'search']
        for param in critical_params:
            assert param in PARAM_SCORES, f"Missing critical param: {param}"

    def test_path_scores_exist(self):
        """Verify key paths are defined"""
        critical_patterns = ['/api/', '/admin', '/debug', '/graphql', r'\.git']
        for pattern in critical_patterns:
            found = any(p[0] == pattern for p in PATH_SCORES)
            assert found, f"Missing critical path pattern: {pattern}"

    def test_tech_scores_exist(self):
        """Verify key technologies are defined"""
        critical_techs = ['php', 'spring', 'wordpress', 'jenkins', 'graphql']
        for tech in critical_techs:
            assert tech in TECH_SCORES, f"Missing critical tech: {tech}"

    def test_noise_patterns_exist(self):
        """Verify noise patterns are defined"""
        assert len(NOISE_PATTERNS) >= 5
        # Check static file pattern exists
        static_found = any('.js' in p[0] or 'js' in p[0] for p in NOISE_PATTERNS)
        assert static_found, "Missing static file noise pattern"

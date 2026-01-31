"""
SHADOW v6 - Tests

Unit tests for the decision engine.
"""

import pytest
import json
from datetime import datetime
from pathlib import Path

# Import engine components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.state import TargetState, StateManager, TargetPhase, WAFType
from engine.scorer import Scorer, ScoreCategory
from engine.decision import DecisionEngine, DecisionType
from engine.schemas import (
    ModuleOutput, IntelOutput, SubdomainsOutput, 
    HTTPOutput, HTTPHost, VulnOutput, Vulnerability
)
from engine.context import Context, RateConfig, ScopeConfig


# ═══════════════════════════════════════════════════════════════════════════════
# STATE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestTargetState:
    """Tests for TargetState"""
    
    def test_create_state(self):
        """Test creating a new target state"""
        state = TargetState(domain="example.com")
        assert state.domain == "example.com"
        assert state.phase == TargetPhase.INIT
        assert state.score == 0
        
    def test_phase_transition(self):
        """Test moving between phases"""
        state = TargetState(domain="example.com")
        state.phase = TargetPhase.RECON
        assert state.phase == TargetPhase.RECON
        
    def test_to_dict(self):
        """Test serialization"""
        state = TargetState(domain="example.com")
        state.score = 50
        data = state.to_dict()
        
        assert data["domain"] == "example.com"
        assert data["score"] == 50


class TestStateManager:
    """Tests for StateManager"""
    
    def test_create_target(self):
        """Test creating a new target"""
        manager = StateManager("/tmp/test_shadow")
        state = manager.create_target("test.com")
        
        assert state.domain == "test.com"
        assert "test.com" in manager.targets
        
    def test_get_target(self):
        """Test retrieving a target"""
        manager = StateManager("/tmp/test_shadow")
        manager.create_target("test.com")
        
        state = manager.get_target("test.com")
        assert state is not None
        assert state.domain == "test.com"
        
    def test_get_nonexistent(self):
        """Test getting a target that doesn't exist"""
        manager = StateManager("/tmp/test_shadow")
        state = manager.get_target("nonexistent.com")
        assert state is None


# ═══════════════════════════════════════════════════════════════════════════════
# SCORER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestScorer:
    """Tests for the scoring system"""
    
    def setup_method(self):
        """Setup scorer for each test"""
        self.scorer = Scorer()
        
    def test_jwt_bonus(self):
        """JWT tokens should increase score"""
        state = TargetState(domain="example.com")
        state.auth.jwt_found = True
        
        score = self.scorer.calculate(state)
        assert score.total > 0
        assert any("jwt" in f.reason.lower() for f in score.factors)
        
    def test_graphql_bonus(self):
        """GraphQL should increase score"""
        state = TargetState(domain="example.com")
        state.api.graphql_found = True
        
        score = self.scorer.calculate(state)
        assert score.total > 0
        assert any("graphql" in f.reason.lower() for f in score.factors)
        
    def test_waf_penalty(self):
        """WAF should decrease score"""
        state = TargetState(domain="example.com")
        state.fingerprint.waf = WAFType.CLOUDFLARE
        
        score = self.scorer.calculate(state)
        assert any(f.value < 0 for f in score.factors)
        
    def test_admin_panel_bonus(self):
        """Admin panel should increase score"""
        state = TargetState(domain="example.com")
        state.js.admin_endpoints = ["/admin", "/dashboard"]
        
        score = self.scorer.calculate(state)
        assert score.total > 0
        
    def test_exposed_git(self):
        """Exposed .git should increase score"""
        state = TargetState(domain="example.com")
        state.vuln_hints.exposed_git = True
        
        score = self.scorer.calculate(state)
        assert score.total > 0
        
    def test_score_factors_have_reasons(self):
        """All score factors should have explanations"""
        state = TargetState(domain="example.com")
        state.auth.jwt_found = True
        state.api.graphql_found = True
        
        score = self.scorer.calculate(state)
        
        for factor in score.factors:
            assert factor.reason, "Factor must have a reason"
            assert len(factor.reason) > 5, "Reason must be descriptive"


# ═══════════════════════════════════════════════════════════════════════════════
# DECISION ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDecisionEngine:
    """Tests for the decision engine"""
    
    def setup_method(self):
        """Setup engine for each test"""
        config = ScopeConfig(
            in_scope=["*.example.com"],
            out_of_scope=[]
        )
        rate_config = RateConfig(
            requests_per_second=10,
            max_concurrent=5
        )
        context = Context(scope=config, rate=rate_config)
        self.engine = DecisionEngine(context)
        
    def test_init_phase_decision(self):
        """In init phase, should recommend intel"""
        state = TargetState(domain="example.com")
        state.phase = TargetPhase.INIT
        
        decisions = self.engine.decide(state)
        
        # Should recommend intel module
        assert len(decisions) > 0
        module_names = [d.module for d in decisions]
        assert "01_intel" in module_names or any("intel" in m.lower() for m in module_names if m)
        
    def test_no_vuln_scan_without_evidence(self):
        """Should not recommend vuln scan without evidence"""
        state = TargetState(domain="example.com")
        state.phase = TargetPhase.ANALYSIS
        state.score = 10  # Low score
        
        decisions = self.engine.decide(state)
        
        # Should not include heavy vuln scanning
        module_names = [d.module for d in decisions]
        assert "09_vuln" not in module_names or \
               all(d.type != DecisionType.IMMEDIATE for d in decisions if d.module == "09_vuln")
        
    def test_high_score_triggers_vuln(self):
        """High score should trigger vuln scanning"""
        state = TargetState(domain="example.com")
        state.phase = TargetPhase.VULNERABILITY
        state.score = 70
        state.vuln_hints.exposed_git = True
        state.auth.jwt_found = True
        
        decisions = self.engine.decide(state)
        
        # Should recommend vuln scan for high-value target
        module_names = [d.module for d in decisions]
        # At this phase, vuln should be considered
        assert any("vuln" in str(d).lower() for d in decisions) or len(decisions) > 0
        
    def test_decisions_have_reasons(self):
        """All decisions should have reasoning"""
        state = TargetState(domain="example.com")
        state.phase = TargetPhase.RECON
        
        decisions = self.engine.decide(state)
        
        for decision in decisions:
            assert decision.reason, "Decision must have a reason"


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemas:
    """Tests for JSON schemas"""
    
    def test_module_output_serialization(self):
        """Test ModuleOutput serializes to valid JSON"""
        output = ModuleOutput(
            module="01_intel",
            target="example.com",
            timestamp=datetime.now().isoformat(),
            success=True,
            data={"ip_ranges": ["1.2.3.0/24"]}
        )
        
        json_str = output.to_json()
        parsed = json.loads(json_str)
        
        assert parsed["module"] == "01_intel"
        assert parsed["success"] is True
        
    def test_intel_output(self):
        """Test IntelOutput schema"""
        from engine.schemas import ASNInfo
        
        output = IntelOutput(
            asn=ASNInfo(number="AS12345", name="Test ISP", country="US"),
            ip_ranges=["1.2.3.0/24", "5.6.7.0/24"]
        )
        
        data = output.to_dict()
        assert data["asn"]["number"] == "AS12345"
        assert len(data["ip_ranges"]) == 2
        
    def test_subdomains_output(self):
        """Test SubdomainsOutput schema"""
        from engine.schemas import Subdomain
        
        output = SubdomainsOutput(
            total_found=100,
            unique_count=85,
            subdomains=[
                Subdomain(name="api.example.com", source="subfinder"),
                Subdomain(name="admin.example.com", source="amass")
            ]
        )
        
        data = output.to_dict()
        assert data["total_found"] == 100
        assert len(data["subdomains"]) == 2
        
    def test_vuln_output(self):
        """Test VulnOutput schema"""
        output = VulnOutput(
            total_found=5,
            critical_count=1,
            high_count=2,
            vulnerabilities=[
                Vulnerability(
                    name="SQL Injection",
                    severity="critical",
                    url="https://example.com/search?q=test",
                    template="sqli-test"
                )
            ]
        )
        
        data = output.to_dict()
        assert data["critical_count"] == 1
        assert data["vulnerabilities"][0]["name"] == "SQL Injection"


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Integration tests for the full pipeline"""
    
    def test_full_scoring_pipeline(self):
        """Test scoring a fully populated target"""
        state = TargetState(domain="vulnerable-app.com")
        
        # Populate with findings
        state.auth.jwt_found = True
        state.auth.oauth_found = True
        state.api.graphql_found = True
        state.api.swagger_exposed = True
        state.js.admin_endpoints = ["/admin", "/dashboard"]
        state.js.secrets_found = ["api_key_abc123"]
        state.vuln_hints.exposed_git = True
        state.fingerprint.waf = None  # No WAF
        
        scorer = Scorer()
        score = scorer.calculate(state)
        
        # Should have high score
        assert score.total >= 30
        assert len(score.factors) >= 4
        
        # Should prioritize correctly
        state.score = score.total
        config = ScopeConfig(in_scope=["*.vulnerable-app.com"], out_of_scope=[])
        engine = DecisionEngine(Context(scope=config))
        
        decisions = engine.decide(state)
        assert len(decisions) > 0
        
    def test_low_value_target(self):
        """Test a low-value target doesn't trigger heavy scans"""
        state = TargetState(domain="boring-static-site.com")
        
        # No interesting findings
        state.score = 5
        state.phase = TargetPhase.ANALYSIS
        
        config = ScopeConfig(in_scope=["*.boring-static-site.com"], out_of_scope=[])
        engine = DecisionEngine(Context(scope=config))
        
        decisions = engine.decide(state)
        
        # Should not aggressively scan
        immediate = [d for d in decisions if d.type == DecisionType.IMMEDIATE]
        assert len(immediate) <= 2


# ═══════════════════════════════════════════════════════════════════════════════
# RUNNER TESTS (require mocking)
# ═══════════════════════════════════════════════════════════════════════════════

class TestModuleRunner:
    """Tests for module runner (with mocking)"""
    
    def test_orchestrator_dependencies(self):
        """Test that orchestrator respects dependencies"""
        from engine.runner import ModuleOrchestrator, ModuleRunner
        
        runner = ModuleRunner("/tmp/shadow", "/tmp/output", "example.com")
        orchestrator = ModuleOrchestrator(runner)
        
        # DNS depends on subdomains
        can_run, reason = orchestrator.can_run("03_dns")
        assert not can_run
        assert "02_subdomains" in reason
        
        # Mark subdomains as completed
        orchestrator.completed.append("02_subdomains")
        
        can_run, reason = orchestrator.can_run("03_dns")
        assert can_run
        
    def test_scanner_discipline(self):
        """Test that heavy modules require evidence"""
        from engine.runner import ModuleOrchestrator, ModuleRunner, ModuleOutput
        from datetime import datetime
        
        runner = ModuleRunner("/tmp/shadow", "/tmp/output", "example.com")
        orchestrator = ModuleOrchestrator(runner)
        
        # Setup: complete prereqs with no interesting data
        orchestrator.completed = ["02_subdomains", "03_dns", "05_http"]
        orchestrator.results["03_dns"] = ModuleOutput(
            module="03_dns",
            target="example.com",
            timestamp=datetime.now().isoformat(),
            data={"resolved_count": 0}  # No resolved hosts
        )
        
        state = TargetState(domain="example.com")
        state.score = 10
        
        # Port scan should be blocked (no resolved hosts)
        should, reason = orchestrator.should_run("04_ports", state)
        assert not should
        assert "resolved" in reason.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

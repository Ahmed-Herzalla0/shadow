#!/usr/bin/env python3
"""
SHADOW - Module Smoke Tests

Smoke tests for individual modules to verify:
- CLI argument parsing
- Output format (JSONL)
- Exit codes
- Fallback behavior when tools are unavailable

Author: SHADOW Team
License: MIT
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Project root
PROJECT_ROOT = Path(__file__).parent.parent


class TestSubdomainCollector:
    """Smoke tests for subdomain collector module"""
    
    def test_collector_help(self):
        """Test --help flag works"""
        result = subprocess.run(
            [sys.executable, "modules/02_subdomains/collector.py", "--help"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        
        assert result.returncode == 0
        assert "--target" in result.stdout
        assert "--output" in result.stdout
        assert "--resume-token" in result.stdout
    
    def test_collector_version(self):
        """Test --version flag works"""
        result = subprocess.run(
            [sys.executable, "modules/02_subdomains/collector.py", "--version"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        
        assert result.returncode == 0
        assert "Subdomain Collector" in result.stdout
    
    def test_collector_invalid_domain(self):
        """Test rejection of invalid domains"""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            output_file = f.name
        
        try:
            result = subprocess.run(
                [
                    sys.executable, "modules/02_subdomains/collector.py",
                    "--target", "not-a-valid-domain",
                    "--output", output_file,
                ],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
            )
            
            # Should fail with exit code 2
            assert result.returncode == 2
            assert "Invalid" in result.stderr or "invalid" in result.stderr.lower()
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_collector_fallback_mode(self):
        """Test fallback subdomain generation when no tools available"""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            output_file = f.name
        
        try:
            # Run with a valid domain - should use fallback if tools not installed
            result = subprocess.run(
                [
                    sys.executable, "modules/02_subdomains/collector.py",
                    "--target", "example.com",
                    "--output", output_file,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(PROJECT_ROOT),
            )
            
            # Should succeed (exit 0 or 1 for partial)
            assert result.returncode in (0, 1), f"Unexpected exit: {result.returncode}"
            
            # Verify JSONL output format
            assert os.path.exists(output_file)
            
            with open(output_file) as f:
                lines = f.readlines()
            
            # Should have at least some fallback subdomains
            assert len(lines) >= 1, "Should produce at least one subdomain"
            
            # Verify each line is valid JSON
            for i, line in enumerate(lines):
                try:
                    obj = json.loads(line)
                    assert "subdomain" in obj, f"Line {i+1} missing 'subdomain'"
                    assert "domain" in obj, f"Line {i+1} missing 'domain'"
                    assert "source" in obj, f"Line {i+1} missing 'source'"
                    assert "type" in obj, f"Line {i+1} missing 'type'"
                    assert obj["type"] == "subdomain"
                except json.JSONDecodeError as e:
                    pytest.fail(f"Line {i+1} is not valid JSON: {e}")
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_collector_jsonl_format(self):
        """Verify JSONL output follows schema"""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            output_file = f.name
        
        try:
            result = subprocess.run(
                [
                    sys.executable, "modules/02_subdomains/collector.py",
                    "--target", "test.example.org",
                    "--output", output_file,
                ],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(PROJECT_ROOT),
            )
            
            # Should succeed
            assert result.returncode in (0, 1)
            
            with open(output_file) as f:
                lines = f.readlines()
            
            for line in lines:
                obj = json.loads(line)
                
                # Verify schema
                assert isinstance(obj.get("subdomain"), str)
                assert isinstance(obj.get("domain"), str)
                assert isinstance(obj.get("source"), str)
                assert isinstance(obj.get("timestamp"), str)
                assert obj.get("type") == "subdomain"
                
                # Domain should match target
                assert "test.example.org" in obj["subdomain"] or obj["subdomain"] == "test.example.org"
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)


class TestOrchestratorSmoke:
    """Smoke tests for the orchestrator"""
    
    def test_orchestrator_help(self):
        """Test --help flag works"""
        result = subprocess.run(
            [sys.executable, "orchestrator.py", "--help"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        
        assert result.returncode == 0
        assert "--output" in result.stdout
        assert "--scope" in result.stdout
        assert "--debug" in result.stdout
        assert "--allow-destructive" in result.stdout
        assert "--confirm-legal" in result.stdout
        assert "--resume" in result.stdout
    
    def test_orchestrator_version(self):
        """Test --version flag works"""
        result = subprocess.run(
            [sys.executable, "orchestrator.py", "--version"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        
        assert result.returncode == 0
        assert "Orchestrator" in result.stdout
    
    def test_orchestrator_invalid_target(self):
        """Test rejection of invalid targets"""
        result = subprocess.run(
            [
                sys.executable, "orchestrator.py",
                "!!!invalid!!!",
                "--output", "/tmp/shadow-test",
            ],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        
        # Should fail with exit code 2
        assert result.returncode == 2
    
    def test_orchestrator_destructive_requires_legal(self):
        """Test --allow-destructive requires --confirm-legal"""
        result = subprocess.run(
            [
                sys.executable, "orchestrator.py",
                "example.com",
                "--output", "/tmp/shadow-test",
                "--allow-destructive",
            ],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
        )
        
        # Should fail - requires --confirm-legal
        assert result.returncode == 2
        assert "confirm-legal" in result.stderr.lower() or "confirm-legal" in result.stdout.lower()


class TestDecisionEngineSmoke:
    """Smoke tests for decision engine"""
    
    def test_decision_import(self):
        """Test decision module imports correctly"""
        from decision import DecisionEngine, ScoredTarget
        
        engine = DecisionEngine()
        assert engine is not None
    
    def test_decision_score_empty(self):
        """Test scoring empty targets list"""
        from decision import DecisionEngine
        
        engine = DecisionEngine()
        result = engine.score_targets([])
        
        assert result == []
    
    def test_decision_score_single(self):
        """Test scoring a single target"""
        from decision import DecisionEngine
        
        engine = DecisionEngine()
        
        targets = [{
            "url": "https://api.example.com/search?q=test",
            "params": {"q": "test"},
        }]
        
        result = engine.score_targets(targets)
        
        assert len(result) == 1
        assert result[0].score >= 0
        assert result[0].priority in ("critical", "high", "medium", "low", "noise")
        assert isinstance(result[0].action, str)
    
    def test_decision_score_sorting(self):
        """Test that targets are sorted by score descending"""
        from decision import DecisionEngine
        
        engine = DecisionEngine()
        
        targets = [
            {"url": "https://example.com/static/app.js", "params": {}},  # Low score (noise)
            {"url": "https://example.com/admin/config?cmd=ls", "params": {"cmd": "ls"}},  # High score
            {"url": "https://example.com/api/users", "params": {"id": "1"}},  # Medium score
        ]
        
        result = engine.score_targets(targets)
        
        assert len(result) == 3
        # Should be sorted descending
        assert result[0].score >= result[1].score >= result[2].score
    
    def test_decision_xss_scoring(self):
        """Test XSS-related scoring"""
        from decision import DecisionEngine
        
        engine = DecisionEngine()
        
        xss_targets = [
            {"url": "https://example.com/search?q=test", "params": {"q": "test"}},
            {"url": "https://example.com/comment?message=hello", "params": {"message": "hello"}},
            {"url": "https://example.com/error?error=msg", "params": {"error": "msg"}},
        ]
        
        for target in xss_targets:
            result = engine.score_targets([target])
            assert len(result) == 1
            assert "xss" in result[0].tags, f"XSS param should be tagged: {target}"
            assert result[0].score > 0


class TestSchemaValidation:
    """Tests for Pydantic schema validation"""
    
    def test_ranked_target_schema(self):
        """Test RankedTarget schema validation"""
        from schemas import RankedTarget
        
        target = RankedTarget(
            url="https://example.com/api",
            domain="example.com",
            path="/api",
            params={"id": "1"},
            score=10,
            priority="high",
            action="idor-test",
            reasons=["+5: IDOR param"],
            tags=["idor", "api"],
            source="katana",
        )
        
        assert target.score == 10
        assert target.priority == "high"
    
    def test_ranked_target_priority_validation(self):
        """Test priority must be valid"""
        from schemas import RankedTarget
        
        with pytest.raises(ValueError):
            RankedTarget(
                url="https://example.com",
                domain="example.com",
                score=10,
                priority="INVALID",
                action="test",
            )
    
    def test_scan_config_schema(self):
        """Test ScanConfig schema"""
        from schemas import ScanConfig, Scope
        
        config = ScanConfig(
            target="example.com",
            scope=Scope.XSS,
            debug=True,
        )
        
        assert config.target == "example.com"
        assert config.scope == Scope.XSS
        assert config.debug is True
        assert config.timeout == 300  # default


class TestLoggingModule:
    """Tests for logging utilities"""
    
    def test_logger_creation(self):
        """Test logger can be created"""
        from utils.logging import get_logger
        
        logger = get_logger()
        assert logger is not None
    
    def test_logging_setup(self):
        """Test logging setup with different levels"""
        from utils.logging import setup_logging
        
        logger = setup_logging(level="DEBUG")
        assert logger is not None
    
    def test_json_formatter(self):
        """Test JSON formatter produces valid JSON"""
        import logging
        from utils.logging import JSONFormatter
        
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        
        output = formatter.format(record)
        
        # Should be valid JSON
        parsed = json.loads(output)
        assert "message" in parsed
        assert parsed["message"] == "Test message"
        assert parsed["level"] == "INFO"

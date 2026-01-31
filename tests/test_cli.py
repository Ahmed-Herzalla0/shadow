#!/usr/bin/env python3
"""
SHADOW - CLI Tests

Tests for CLI entry point and orchestrator.
"""

import os
import subprocess
import sys
from pathlib import Path

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent
SHADOW_CLI = PROJECT_ROOT / "shadow"


class TestCLISmoke:
    """Smoke tests for CLI"""

    def test_cli_exists(self):
        """Test that CLI script exists"""
        assert SHADOW_CLI.exists(), "shadow CLI script should exist"

    def test_cli_executable(self):
        """Test that CLI is executable"""
        assert os.access(SHADOW_CLI, os.X_OK), "shadow CLI should be executable"

    def test_cli_help(self):
        """Test --help flag"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "SHADOW" in result.stdout or "shadow" in result.stdout.lower()
        assert "hunt" in result.stdout
        assert "top" in result.stdout
        assert "export" in result.stdout

    def test_cli_hunt_help(self):
        """Test hunt subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "hunt", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "target" in result.stdout.lower()

    def test_cli_top_help(self):
        """Test top subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "top", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "limit" in result.stdout.lower() or "-l" in result.stdout

    def test_cli_export_help(self):
        """Test export subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "export", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "score" in result.stdout.lower() or "-m" in result.stdout

    def test_cli_stats_help(self):
        """Test stats subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "stats", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0

    def test_cli_no_args(self):
        """Test CLI with no arguments shows help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI)],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Should exit with code 0 and show help
        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "SHADOW" in result.stdout

    def test_cli_top_no_scan(self, tmp_path):
        """Test top command when no scan exists"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "top", "nonexistent.com",
             "-o", str(tmp_path / "output")],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Should fail gracefully
        assert result.returncode == 1
        assert "not found" in result.stdout.lower() or "No ranked" in result.stdout


class TestCLIVersion:
    """Version and metadata tests"""

    def test_cli_version(self):
        """Test --version flag"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "3.0" in result.stdout or "SHADOW" in result.stdout


class TestCLIWithRankedTargets:
    """Integration tests with ranked target files"""

    def test_cli_top_with_ranked_file(self, tmp_path):
        """Test top command with ranked targets file"""
        import json
        
        output_dir = tmp_path / "output" / "example.com"
        output_dir.mkdir(parents=True)
        
        # Create mock ranked targets file
        ranked_file = output_dir / "targets_ranked.json"
        ranked_data = {
            "metadata": {"scope": "xss", "scan_time": "10s"},
            "targets": [
                {"url": "https://example.com/admin", "score": 15, "priority": "critical",
                 "action": "Manual test", "reasons": ["+4: admin path"], "tags": ["admin"]},
                {"url": "https://example.com/api", "score": 5, "priority": "medium",
                 "action": "Automated scan", "reasons": ["+3: api path"], "tags": ["api"]},
            ]
        }
        with open(ranked_file, "w") as f:
            json.dump(ranked_data, f)

        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "top", "example.com",
             "-o", str(output_dir), "-l", "5"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0, f"Failed: {result.stdout} {result.stderr}"
        assert "CRITICAL" in result.stdout
        assert "example.com/admin" in result.stdout

    def test_cli_export_urls(self, tmp_path):
        """Test export command outputs URLs"""
        import json
        
        output_dir = tmp_path / "output" / "example.com"
        output_dir.mkdir(parents=True)
        
        ranked_file = output_dir / "targets_ranked.json"
        ranked_data = {
            "metadata": {"scope": "xss"},
            "targets": [
                {"url": "https://example.com/admin?id=1", "score": 10, "priority": "high",
                 "action": "Test", "reasons": [], "tags": []},
            ]
        }
        with open(ranked_file, "w") as f:
            json.dump(ranked_data, f)

        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "export", "example.com",
             "-o", str(output_dir), "-m", "5"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0, f"Failed: {result.stdout} {result.stderr}"
        assert "https://example.com/admin?id=1" in result.stdout

    def test_cli_stats(self, tmp_path):
        """Test stats command"""
        import json
        
        output_dir = tmp_path / "output" / "example.com"
        output_dir.mkdir(parents=True)
        
        ranked_file = output_dir / "targets_ranked.json"
        ranked_data = {
            "metadata": {"scope": "xss", "scan_time": "10s"},
            "targets": [
                {"url": "https://example.com/admin", "score": 15, "priority": "critical",
                 "action": "Test", "reasons": [], "tags": ["admin", "idor"]},
                {"url": "https://example.com/api", "score": 5, "priority": "medium",
                 "action": "Test", "reasons": [], "tags": ["api"]},
            ]
        }
        with open(ranked_file, "w") as f:
            json.dump(ranked_data, f)

        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "stats", "example.com",
             "-o", str(output_dir)],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0, f"Failed: {result.stdout} {result.stderr}"
        assert "Total targets: 2" in result.stdout
        assert "critical" in result.stdout.lower()


class TestOrchestratorSmoke:
    """Smoke tests for the new orchestrator"""

    def test_import_orchestrator(self):
        """Test that orchestrator can be imported"""
        from orchestrator import Orchestrator, MODULES, VERSION

        assert Orchestrator is not None
        assert isinstance(MODULES, dict)
        assert VERSION == "3.0.0"

    def test_modules_have_enabled_flag(self):
        """Test that all modules have enabled flag"""
        from orchestrator import MODULES

        for name, config in MODULES.items():
            assert "enabled" in config, f"Module {name} missing 'enabled' flag"
            assert "script" in config, f"Module {name} missing 'script' field"
            assert "scopes" in config, f"Module {name} missing 'scopes' field"

    def test_decision_engine_import(self):
        """Test that decision engine can be imported"""
        from decision.decision import DecisionEngine, DEFAULT_WEIGHTS

        engine = DecisionEngine()
        assert engine is not None
        assert isinstance(DEFAULT_WEIGHTS, dict)

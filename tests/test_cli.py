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
        assert "domain" in result.stdout.lower()

    def test_cli_top_help(self):
        """Test top subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "top", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "limit" in result.stdout.lower() or "-n" in result.stdout

    def test_cli_export_help(self):
        """Test export subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "export", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "score" in result.stdout.lower() or "-s" in result.stdout

    def test_cli_stats_help(self):
        """Test stats subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "stats", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0

    def test_cli_query_help(self):
        """Test query subcommand help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "query", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0
        assert "sql" in result.stdout.lower()

    def test_cli_no_args(self):
        """Test CLI with no arguments shows help"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI)],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Should exit with code 1 and show help
        assert result.returncode == 1
        assert "usage" in result.stdout.lower() or "usage" in result.stderr.lower()

    def test_cli_top_no_db(self, tmp_path):
        """Test top command when database doesn't exist"""
        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "top", "nonexistent.com",
             "-o", str(tmp_path / "output")],
            capture_output=True,
            text=True,
            timeout=10
        )

        # Should fail gracefully
        assert result.returncode == 1
        assert "not found" in result.stdout.lower() or "not found" in result.stderr.lower()


class TestCLIIntegration:
    """Integration tests with actual database"""

    def test_cli_stats_with_db(self, tmp_path, populated_db):
        """Test stats command with populated database"""
        # Move populated_db to expected location
        import shutil
        output_dir = tmp_path / "output" / "example.com"
        output_dir.mkdir(parents=True)
        db_dest = output_dir / "shadow.db"

        # Copy database - close first to flush
        populated_db.conn.commit()
        shutil.copy(populated_db.db_path, db_dest)

        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "stats", "example.com",
             "-o", str(output_dir)],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0, f"Failed: {result.stdout} {result.stderr}"
        assert "Assets" in result.stdout or "assets" in result.stdout.lower()

    def test_cli_top_with_db(self, tmp_path, populated_db):
        """Test top command with populated database"""
        import shutil
        output_dir = tmp_path / "output" / "example.com"
        output_dir.mkdir(parents=True)
        db_dest = output_dir / "shadow.db"

        populated_db.conn.commit()
        shutil.copy(populated_db.db_path, db_dest)

        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "top", "example.com",
             "-o", str(output_dir), "-n", "5"],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0, f"Failed: {result.stdout} {result.stderr}"
        assert "TOP" in result.stdout or "Score" in result.stdout

    def test_cli_export_with_db(self, tmp_path, populated_db):
        """Test export command with populated database"""
        import shutil
        output_dir = tmp_path / "output" / "example.com"
        output_dir.mkdir(parents=True)
        db_dest = output_dir / "shadow.db"

        populated_db.conn.commit()
        shutil.copy(populated_db.db_path, db_dest)

        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "export", "example.com",
             "-o", str(output_dir)],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0, f"Failed: {result.stdout} {result.stderr}"
        # Should output URLs
        assert "http" in result.stdout

    def test_cli_query_with_db(self, tmp_path, populated_db):
        """Test query command with populated database"""
        import shutil
        output_dir = tmp_path / "output" / "example.com"
        output_dir.mkdir(parents=True)
        db_dest = output_dir / "shadow.db"

        populated_db.conn.commit()
        shutil.copy(populated_db.db_path, db_dest)

        result = subprocess.run(
            [sys.executable, str(SHADOW_CLI), "query", "example.com",
             "SELECT COUNT(*) as cnt FROM endpoints",
             "-o", str(output_dir)],
            capture_output=True,
            text=True,
            timeout=10
        )

        assert result.returncode == 0, f"Failed: {result.stdout} {result.stderr}"
        assert "cnt" in result.stdout


class TestCollectorSmoke:
    """Smoke tests for collectors (no external tools required)"""

    def test_import_collectors(self):
        """Test that collectors can be imported"""
        from core.collectors import (
            BaseCollector,
            Orchestrator,
        )

        assert BaseCollector is not None
        assert Orchestrator is not None

    def test_orchestrator_init(self, tmp_path):
        """Test Orchestrator initialization"""
        from core.collectors import Orchestrator

        db_path = str(tmp_path / "test.db")
        orch = Orchestrator(db_path)

        assert orch.db is not None
        assert orch.subdomains is not None
        assert orch.http is not None

        orch.close()

    def test_base_collector_tool_check(self, temp_db):
        """Test tool existence check"""
        from core.collectors import BaseCollector

        collector = BaseCollector(temp_db)

        # Check for common tools
        assert collector.tool_exists('ls') == True
        assert collector.tool_exists('nonexistent_tool_xyz') == False

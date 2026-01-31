#!/usr/bin/env python3
"""
SHADOW Orchestrator - Decision-Driven Recon Orchestration

This orchestrator spawns modules as subprocesses, reads their JSONL outputs,
persists state for resume capability, and calls the Decision Engine to produce
ranked targets.

Scope: XSS-focused endpoint discovery & validation
Justification: Non-destructive, highly automatable, immediate actionable results.

Usage:
    ./orchestrator.py target.com --output outdir --scope xss --debug
    ./orchestrator.py target.com --resume --output outdir
    ./orchestrator.py target.com --allow-destructive --confirm-legal

Author: SHADOW Team
License: MIT
"""

from __future__ import annotations

import argparse
import json
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from decision.decision import DecisionEngine
from schemas.target import RankedTarget
from utils.logging import get_logger, setup_logging

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "3.0.0"
DEFAULT_TIMEOUT = 300  # 5 minutes per module
DEFAULT_RETRIES = 2
BACKOFF_BASE = 5  # seconds

# Module definitions with scope mapping
MODULES = {
    "subdomains": {
        "script": "modules/02_subdomains/collector.py",
        "timeout": 600,
        "scopes": ["xss", "full", "api", "js"],
        "destructive": False,
    },
    "dns": {
        "script": "modules/03_dns.sh",
        "timeout": 300,
        "scopes": ["xss", "full"],
        "destructive": False,
    },
    "http": {
        "script": "modules/05_http.sh",
        "timeout": 600,
        "scopes": ["xss", "full", "api", "js"],
        "destructive": False,
    },
    "content": {
        "script": "modules/06_content.sh",
        "timeout": 900,
        "scopes": ["xss", "full", "js"],
        "destructive": False,
    },
    "js": {
        "script": "modules/07_js.sh",
        "timeout": 600,
        "scopes": ["xss", "js", "full"],
        "destructive": False,
    },
    "params": {
        "script": "modules/08_params.sh",
        "timeout": 600,
        "scopes": ["xss", "full"],
        "destructive": False,
    },
    "vuln_xss": {
        "script": "modules/09_vuln.sh",
        "timeout": 1800,
        "scopes": ["xss"],
        "destructive": True,  # Uses nuclei with payloads
        "templates": "xss",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ResumeState:
    """State for resuming interrupted scans"""
    target: str
    scope: str
    started_at: str
    last_update: str
    completed_modules: List[str] = field(default_factory=list)
    current_module: Optional[str] = None
    error_count: int = 0
    last_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResumeState:
        return cls(**data)

    @classmethod
    def new(cls, target: str, scope: str) -> ResumeState:
        now = datetime.utcnow().isoformat()
        return cls(
            target=target,
            scope=scope,
            started_at=now,
            last_update=now,
        )


@dataclass
class ModuleExecution:
    """Result of a module execution"""
    module_name: str
    success: bool
    exit_code: int
    duration_seconds: float
    output_file: Optional[str] = None
    error_message: Optional[str] = None
    lines_produced: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# STATE MANAGER (SQLite-backed)
# ═══════════════════════════════════════════════════════════════════════════════

class StateStore:
    """SQLite-backed state store with atomic commits"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.state_file = output_dir / "state.json"
        self._state: Optional[ResumeState] = None

    def load(self) -> Optional[ResumeState]:
        """Load state from disk"""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                self._state = ResumeState.from_dict(data)
                return self._state
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                get_logger().warning(f"Corrupted state file, starting fresh: {e}")
                return None
        return None

    def save(self, state: ResumeState) -> None:
        """Atomically save state to disk"""
        self._state = state
        state.last_update = datetime.utcnow().isoformat()

        # Write to temp file first, then rename (atomic on POSIX)
        temp_file = self.state_file.with_suffix(".tmp")
        with open(temp_file, "w") as f:
            json.dump(state.to_dict(), f, indent=2)
        temp_file.rename(self.state_file)

    def mark_module_started(self, module_name: str) -> None:
        """Mark a module as currently running"""
        if self._state:
            self._state.current_module = module_name
            self.save(self._state)

    def mark_module_completed(self, module_name: str) -> None:
        """Mark a module as completed"""
        if self._state:
            self._state.current_module = None
            if module_name not in self._state.completed_modules:
                self._state.completed_modules.append(module_name)
            self.save(self._state)

    def record_error(self, error: str) -> None:
        """Record an error"""
        if self._state:
            self._state.error_count += 1
            self._state.last_error = error
            self.save(self._state)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

class ModuleRunner:
    """Runs modules as subprocesses with timeouts and retries"""

    def __init__(
        self,
        output_dir: Path,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        debug: bool = False,
    ):
        self.output_dir = output_dir
        self.timeout = timeout
        self.retries = retries
        self.debug = debug
        self.log = get_logger()

        # Create output subdirectories
        (output_dir / "raw").mkdir(parents=True, exist_ok=True)
        (output_dir / "data").mkdir(parents=True, exist_ok=True)
        (output_dir / "reports").mkdir(parents=True, exist_ok=True)

    def run_module(
        self,
        module_name: str,
        target: str,
        resume_token: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ) -> ModuleExecution:
        """
        Run a module with timeout, retries, and proper error handling.
        
        Returns ModuleExecution with results and output file path.
        """
        module_config = MODULES.get(module_name)
        if not module_config:
            return ModuleExecution(
                module_name=module_name,
                success=False,
                exit_code=-1,
                duration_seconds=0,
                error_message=f"Unknown module: {module_name}",
            )

        script_path = PROJECT_ROOT / module_config["script"]
        module_timeout = module_config.get("timeout", self.timeout)
        output_file = self.output_dir / "raw" / f"{module_name}.jsonl"

        # Build command
        if script_path.suffix == ".py":
            cmd = [sys.executable, str(script_path)]
        else:
            cmd = ["bash", str(script_path)]

        cmd.extend([
            "--target", target,
            "--output", str(output_file),
        ])

        if resume_token:
            cmd.extend(["--resume-token", resume_token])

        if extra_args:
            cmd.extend(extra_args)

        # Run with retries
        last_error = None
        for attempt in range(self.retries + 1):
            start_time = time.time()

            try:
                self.log.info(f"Running {module_name} (attempt {attempt + 1}/{self.retries + 1})")

                if self.debug:
                    self.log.debug(f"Command: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=module_timeout,
                    cwd=str(PROJECT_ROOT),
                )

                duration = time.time() - start_time

                if result.returncode == 0:
                    lines = self._count_lines(output_file)
                    self.log.info(f"✓ {module_name} completed in {duration:.1f}s ({lines} lines)")

                    return ModuleExecution(
                        module_name=module_name,
                        success=True,
                        exit_code=0,
                        duration_seconds=duration,
                        output_file=str(output_file),
                        lines_produced=lines,
                    )
                else:
                    last_error = result.stderr[:500] if result.stderr else f"Exit code {result.returncode}"
                    self.log.warning(f"Module {module_name} failed: {last_error[:100]}")

            except subprocess.TimeoutExpired:
                duration = time.time() - start_time
                last_error = f"Timeout after {module_timeout}s"
                self.log.warning(f"Module {module_name} timed out after {module_timeout}s")

            except FileNotFoundError:
                return ModuleExecution(
                    module_name=module_name,
                    success=False,
                    exit_code=-1,
                    duration_seconds=0,
                    error_message=f"Script not found: {script_path}",
                )

            except Exception as e:
                last_error = str(e)
                self.log.error(f"Unexpected error running {module_name}: {e}")

            # Backoff before retry
            if attempt < self.retries:
                backoff = BACKOFF_BASE * (2 ** attempt)
                self.log.info(f"Retrying in {backoff}s...")
                time.sleep(backoff)

        # All retries exhausted
        return ModuleExecution(
            module_name=module_name,
            success=False,
            exit_code=-1,
            duration_seconds=time.time() - start_time,
            error_message=last_error,
        )

    def _count_lines(self, file_path: Path) -> int:
        """Count lines in a file"""
        if not file_path.exists():
            return 0
        try:
            with open(file_path) as f:
                return sum(1 for _ in f)
        except Exception:
            return 0


# ═══════════════════════════════════════════════════════════════════════════════
# JSONL READER
# ═══════════════════════════════════════════════════════════════════════════════

class JSONLReader:
    """Read and parse JSONL output files from modules"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.log = get_logger()

    def read_all(self) -> List[Dict[str, Any]]:
        """Read all JSONL files from raw/ directory"""
        raw_dir = self.output_dir / "raw"
        results = []

        if not raw_dir.exists():
            return results

        for jsonl_file in raw_dir.glob("*.jsonl"):
            try:
                results.extend(self._read_file(jsonl_file))
            except Exception as e:
                self.log.warning(f"Error reading {jsonl_file}: {e}")

        return results

    def read_module(self, module_name: str) -> List[Dict[str, Any]]:
        """Read JSONL output from a specific module"""
        jsonl_file = self.output_dir / "raw" / f"{module_name}.jsonl"
        if jsonl_file.exists():
            return self._read_file(jsonl_file)
        return []

    def _read_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Read and parse a JSONL file with error handling"""
        results = []
        line_num = 0

        with open(file_path) as f:
            for line in f:
                line_num += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    obj = json.loads(line)
                    results.append(obj)
                except json.JSONDecodeError as e:
                    self.log.debug(f"Skipping malformed JSON at {file_path}:{line_num}: {e}")

        return results


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class Orchestrator:
    """Main orchestrator that coordinates modules and decision engine"""

    def __init__(
        self,
        target: str,
        output_dir: Path,
        scope: str = "xss",
        debug: bool = False,
        allow_destructive: bool = False,
        confirm_legal: bool = False,
    ):
        self.target = target
        self.output_dir = output_dir
        self.scope = scope
        self.debug = debug
        self.allow_destructive = allow_destructive
        self.confirm_legal = confirm_legal

        self.log = get_logger()
        self.state_store = StateStore(output_dir)
        self.module_runner = ModuleRunner(output_dir, debug=debug)
        self.jsonl_reader = JSONLReader(output_dir)
        self.decision_engine = DecisionEngine()

        self._shutdown_requested = False

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame):
        """Handle graceful shutdown"""
        self.log.warning("Shutdown requested, saving state...")
        self._shutdown_requested = True

    def run(self, resume: bool = False) -> int:
        """
        Run the orchestration pipeline.
        
        Returns exit code (0 = success, 1 = partial failure, 2 = fatal error)
        """
        # Load or create state
        state = None
        if resume:
            state = self.state_store.load()
            if state:
                self.log.info(f"Resuming scan from state: {len(state.completed_modules)} modules completed")
            else:
                self.log.info("No previous state found, starting fresh")

        if not state:
            state = ResumeState.new(self.target, self.scope)

        self.state_store.save(state)

        # Determine which modules to run based on scope
        modules_to_run = self._get_modules_for_scope(state.completed_modules)

        if not modules_to_run:
            self.log.info("All modules already completed")
        else:
            self.log.info(f"Running {len(modules_to_run)} modules for scope '{self.scope}'")

        # Run modules
        results = []
        for module_name in modules_to_run:
            if self._shutdown_requested:
                self.log.warning("Shutdown requested, stopping")
                break

            # Check if module requires --allow-destructive
            module_config = MODULES.get(module_name, {})
            if module_config.get("destructive") and not self.allow_destructive:
                self.log.warning(f"Skipping {module_name}: requires --allow-destructive flag")
                continue

            if module_config.get("destructive") and not self.confirm_legal:
                self.log.warning(f"Skipping {module_name}: requires --confirm-legal flag")
                continue

            self.state_store.mark_module_started(module_name)

            result = self.module_runner.run_module(
                module_name=module_name,
                target=self.target,
            )
            results.append(result)

            if result.success:
                self.state_store.mark_module_completed(module_name)
            else:
                self.state_store.record_error(result.error_message or "Unknown error")

        # Generate reports
        self.log.info("Generating ranked targets report...")
        exit_code = self._generate_reports()

        # Summary
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful

        self.log.info(f"Orchestration complete: {successful} succeeded, {failed} failed")

        if failed > 0 and successful == 0:
            return 2  # Fatal error
        elif failed > 0:
            return 1  # Partial failure
        return exit_code

    def _get_modules_for_scope(self, completed: List[str]) -> List[str]:
        """Get list of modules to run based on scope, excluding completed ones"""
        modules = []
        for name, config in MODULES.items():
            if self.scope in config.get("scopes", []):
                if name not in completed:
                    modules.append(name)
        return modules

    def _generate_reports(self) -> int:
        """Generate ranked targets report using Decision Engine"""
        try:
            # Read all collected data
            all_data = self.jsonl_reader.read_all()

            if not all_data:
                self.log.warning("No data collected, creating empty report")
                all_data = []

            # Score and rank targets
            scored_targets = self.decision_engine.score_targets(all_data)

            # Convert to output format
            ranked_targets = [
                RankedTarget(
                    url=t.url,
                    domain=t.domain,
                    path=t.path,
                    params=t.params,
                    score=t.score,
                    priority=t.priority,
                    action=t.action,
                    reasons=t.reasons,
                    tags=t.tags,
                    source=t.source,
                ).model_dump()
                for t in scored_targets[:100]  # Top 100
            ]

            # Write report
            report_file = self.output_dir / "reports" / "targets_ranked.json"
            with open(report_file, "w") as f:
                json.dump({
                    "generated_at": datetime.utcnow().isoformat(),
                    "target": self.target,
                    "scope": self.scope,
                    "total_scored": len(scored_targets),
                    "targets": ranked_targets,
                }, f, indent=2)

            self.log.info(f"✓ Report written to {report_file}")
            self.log.info(f"  Top target: {ranked_targets[0]['url'] if ranked_targets else 'None'} (score: {ranked_targets[0]['score'] if ranked_targets else 0})")

            return 0

        except Exception as e:
            self.log.error(f"Failed to generate reports: {e}")
            return 2


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="shadow",
        description="SHADOW - Decision-Driven Recon Orchestrator",
        epilog="""
Examples:
  %(prog)s target.com --output outdir --scope xss
  %(prog)s target.com --resume --output outdir
  %(prog)s target.com --allow-destructive --confirm-legal

Scopes:
  xss    - XSS-focused endpoint discovery (default)
  api    - API attack surface mapping
  js     - JavaScript-heavy endpoint discovery
  full   - Complete reconnaissance

Legal Notice:
  This tool is for AUTHORIZED security testing ONLY.
  You must have written permission before scanning any target.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        help="Target domain to scan (e.g., example.com)",
    )

    parser.add_argument(
        "-o", "--output",
        default="output",
        help="Output directory (default: output)",
    )

    parser.add_argument(
        "-s", "--scope",
        choices=["xss", "api", "js", "full"],
        default="xss",
        help="Scan scope (default: xss)",
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from previous state",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    parser.add_argument(
        "--allow-destructive",
        action="store_true",
        help="Allow modules that perform invasive actions (e.g., nuclei exploit templates)",
    )

    parser.add_argument(
        "--confirm-legal",
        action="store_true",
        help="Confirm you have legal authorization to scan this target",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SHADOW Orchestrator v{VERSION}",
    )

    return parser


def validate_target(target: str) -> str:
    """Validate and normalize target domain"""
    import re

    # Remove protocol if present
    target = re.sub(r"^https?://", "", target)

    # Remove trailing slashes and paths
    target = target.split("/")[0]

    # Basic domain validation
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", target):
        raise ValueError(f"Invalid target domain: {target}")

    return target.lower()


def main() -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    log_level = "DEBUG" if args.debug else "INFO"
    setup_logging(level=log_level)
    log = get_logger()

    # Validate target
    try:
        target = validate_target(args.target)
    except ValueError as e:
        log.error(str(e))
        return 2

    # Create output directory with target name
    output_dir = Path(args.output) / target
    output_dir.mkdir(parents=True, exist_ok=True)

    # Legal warning for destructive modules
    if args.allow_destructive and not args.confirm_legal:
        log.error("--allow-destructive requires --confirm-legal flag")
        log.error("You must confirm legal authorization before running invasive modules")
        return 2

    # Show banner
    log.info(f"SHADOW Orchestrator v{VERSION}")
    log.info(f"Target: {target}")
    log.info(f"Scope: {args.scope}")
    log.info(f"Output: {output_dir}")

    # Run orchestrator
    orchestrator = Orchestrator(
        target=target,
        output_dir=output_dir,
        scope=args.scope,
        debug=args.debug,
        allow_destructive=args.allow_destructive,
        confirm_legal=args.confirm_legal,
    )

    return orchestrator.run(resume=args.resume)


if __name__ == "__main__":
    sys.exit(main())

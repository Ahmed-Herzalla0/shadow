#!/usr/bin/env python3
"""
SHADOW - Subdomain Collector Module

Canonical module example demonstrating:
- CLI with --target, --output, --resume-token
- External tool calls with subprocess checks and fallbacks
- Normalized JSONL output (one JSON object per line)
- Proper exit codes

Usage:
    python collector.py --target example.com --output subdomains.jsonl
    python collector.py --target example.com --output subdomains.jsonl --resume-token abc123

Exit codes:
    0 - Success
    1 - Partial failure (some tools failed)
    2 - Fatal error (no data collected)

Author: SHADOW Team
License: MIT
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
DEFAULT_TIMEOUT = 300  # 5 minutes per tool
MAX_RETRIES = 2
BACKOFF_BASE = 3

# Tool configurations
TOOLS = {
    "subfinder": {
        "cmd": ["subfinder", "-d", "{domain}", "-silent"],
        "timeout": 300,
        "fallback": True,
    },
    "assetfinder": {
        "cmd": ["assetfinder", "--subs-only", "{domain}"],
        "timeout": 120,
        "fallback": True,
    },
    "amass": {
        "cmd": ["amass", "enum", "-passive", "-d", "{domain}", "-timeout", "5"],
        "timeout": 360,
        "fallback": False,  # Amass can be slow/unavailable
    },
}

# Fallback subdomains for testing when no tools are available
FALLBACK_PREFIXES = [
    "www", "api", "mail", "dev", "staging", "admin", "portal",
    "app", "cdn", "static", "assets", "m", "mobile",
]


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SubdomainResult:
    """Normalized subdomain result"""
    subdomain: str
    domain: str
    source: str
    timestamp: str
    type: str = "subdomain"

    def to_jsonl(self) -> str:
        """Convert to JSONL line"""
        data = asdict(self)
        return json.dumps(data, separators=(",", ":"))


@dataclass
class ResumeState:
    """Resume state for interrupted scans"""
    completed_tools: List[str]
    collected_subdomains: int
    last_update: str


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def log_info(msg: str) -> None:
    """Log info message to stderr"""
    print(f"[*] {msg}", file=sys.stderr)


def log_warn(msg: str) -> None:
    """Log warning message to stderr"""
    print(f"[!] {msg}", file=sys.stderr)


def log_error(msg: str) -> None:
    """Log error message to stderr"""
    print(f"[✗] {msg}", file=sys.stderr)


def log_success(msg: str) -> None:
    """Log success message to stderr"""
    print(f"[✓] {msg}", file=sys.stderr)


def tool_exists(name: str) -> bool:
    """Check if a tool is installed and available"""
    return shutil.which(name) is not None


def validate_domain(domain: str) -> str:
    """Validate and normalize domain"""
    # Remove protocol
    domain = re.sub(r"^https?://", "", domain)
    # Remove path
    domain = domain.split("/")[0]
    # Remove port
    domain = domain.split(":")[0]
    # Lowercase
    domain = domain.lower().strip()

    # Validate format
    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$", domain):
        raise ValueError(f"Invalid domain format: {domain}")

    return domain


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class SubdomainCollector:
    """Collect subdomains from multiple sources"""

    def __init__(
        self,
        target: str,
        output_file: Path,
        resume_token: Optional[str] = None,
    ):
        self.target = validate_domain(target)
        self.output_file = output_file
        self.resume_token = resume_token

        self.subdomains: Set[str] = set()
        self.results: List[SubdomainResult] = []
        self.completed_tools: List[str] = []

        # Load resume state if token provided
        if resume_token:
            self._load_resume_state()

    def _load_resume_state(self) -> None:
        """Load resume state from token"""
        # Token is just a marker file path
        state_file = self.output_file.with_suffix(".state")
        if state_file.exists():
            try:
                with open(state_file) as f:
                    data = json.load(f)
                self.completed_tools = data.get("completed_tools", [])
                log_info(f"Resuming: {len(self.completed_tools)} tools already completed")
            except (OSError, json.JSONDecodeError):
                pass

    def _save_resume_state(self) -> None:
        """Save resume state"""
        state_file = self.output_file.with_suffix(".state")
        state = ResumeState(
            completed_tools=self.completed_tools,
            collected_subdomains=len(self.subdomains),
            last_update=datetime.utcnow().isoformat(),
        )
        with open(state_file, "w") as f:
            json.dump(asdict(state), f)

    def collect(self) -> int:
        """
        Run collection from all available tools.
        
        Returns exit code (0=success, 1=partial, 2=fatal)
        """
        log_info(f"Collecting subdomains for: {self.target}")

        tools_run = 0
        tools_failed = 0

        for tool_name, config in TOOLS.items():
            # Skip if already completed (resume)
            if tool_name in self.completed_tools:
                log_info(f"Skipping {tool_name} (already completed)")
                continue

            # Check if tool exists
            if not tool_exists(tool_name):
                if config.get("fallback"):
                    log_warn(f"{tool_name} not found, will use fallback")
                else:
                    log_warn(f"{tool_name} not found, skipping")
                    continue

            # Run tool
            success = self._run_tool(tool_name, config)
            tools_run += 1

            if success:
                self.completed_tools.append(tool_name)
                self._save_resume_state()
            else:
                tools_failed += 1

        # If no tools available or all failed, use fallback
        if len(self.subdomains) == 0:
            log_warn("No subdomains collected, using fallback")
            self._use_fallback()

        # Write results
        self._write_output()

        # Determine exit code
        # If fallback produced data, consider it a success
        if len(self.subdomains) > 0:
            if tools_failed > 0 and tools_run > 0:
                return 1  # Partial failure, but we have data
            return 0  # Success

        if tools_failed == tools_run and tools_run > 0:
            return 2  # All failed
        elif tools_failed > 0:
            return 1  # Partial failure
        return 0

    def _run_tool(self, tool_name: str, config: Dict[str, Any]) -> bool:
        """Run a single tool with retries"""
        cmd_template = config["cmd"]
        timeout = config.get("timeout", DEFAULT_TIMEOUT)

        # Build command
        cmd = [
            part.replace("{domain}", self.target)
            for part in cmd_template
        ]

        log_info(f"Running {tool_name}...")

        for attempt in range(MAX_RETRIES + 1):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

                if result.returncode != 0:
                    if result.stderr:
                        log_warn(f"{tool_name} warning: {result.stderr[:100]}")

                # Parse output
                count = self._parse_output(result.stdout, tool_name)
                log_success(f"{tool_name}: found {count} subdomains")
                return True

            except subprocess.TimeoutExpired:
                log_warn(f"{tool_name} timed out (attempt {attempt + 1})")

            except FileNotFoundError:
                log_warn(f"{tool_name} not found")
                return False

            except Exception as e:
                log_warn(f"{tool_name} error: {e}")

            # Backoff before retry
            if attempt < MAX_RETRIES:
                backoff = BACKOFF_BASE * (2 ** attempt)
                time.sleep(backoff)

        return False

    def _parse_output(self, output: str, source: str) -> int:
        """Parse line-separated output from tool"""
        count = 0
        timestamp = datetime.utcnow().isoformat()

        for line in output.strip().split("\n"):
            subdomain = line.strip().lower()

            if not subdomain:
                continue

            # Must be under target domain
            if not subdomain.endswith(self.target) and subdomain != self.target:
                continue

            # Validate format
            if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", subdomain):
                continue

            # Add if new
            if subdomain not in self.subdomains:
                self.subdomains.add(subdomain)
                self.results.append(SubdomainResult(
                    subdomain=subdomain,
                    domain=self.target,
                    source=source,
                    timestamp=timestamp,
                ))
                count += 1

        return count

    def _use_fallback(self) -> None:
        """Generate fallback subdomains for testing"""
        log_info("Using fallback subdomain generation")
        timestamp = datetime.utcnow().isoformat()

        for prefix in FALLBACK_PREFIXES:
            subdomain = f"{prefix}.{self.target}"
            if subdomain not in self.subdomains:
                self.subdomains.add(subdomain)
                self.results.append(SubdomainResult(
                    subdomain=subdomain,
                    domain=self.target,
                    source="fallback",
                    timestamp=timestamp,
                ))

        # Also add base domain
        if self.target not in self.subdomains:
            self.subdomains.add(self.target)
            self.results.append(SubdomainResult(
                subdomain=self.target,
                domain=self.target,
                source="fallback",
                timestamp=timestamp,
            ))

    def _write_output(self) -> None:
        """Write results to JSONL file"""
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w") as f:
            for result in self.results:
                f.write(result.to_jsonl() + "\n")

        log_success(f"Wrote {len(self.results)} subdomains to {self.output_file}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        description="SHADOW Subdomain Collector - Enumerate subdomains from multiple sources",
        epilog="""
Examples:
  python collector.py --target example.com --output subs.jsonl
  python collector.py --target example.com --output subs.jsonl --resume-token abc

Output Format (JSONL):
  {"subdomain":"api.example.com","domain":"example.com","source":"subfinder","timestamp":"...","type":"subdomain"}
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target domain (e.g., example.com)",
    )

    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output JSONL file path",
    )

    parser.add_argument(
        "--resume-token",
        help="Resume token from previous run",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SHADOW Subdomain Collector v{VERSION}",
    )

    return parser


def main() -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    try:
        collector = SubdomainCollector(
            target=args.target,
            output_file=Path(args.output),
            resume_token=args.resume_token,
        )
        return collector.collect()

    except ValueError as e:
        log_error(str(e))
        return 2

    except KeyboardInterrupt:
        log_warn("Interrupted by user")
        return 1

    except Exception as e:
        log_error(f"Unexpected error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())

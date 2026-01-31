#!/usr/bin/env python3
"""
SHADOW v6 - Intelligence-Driven Bug Bounty Decision Engine

Usage:
    python3 -m engine.main <target> [options]
    
Examples:
    python3 -m engine.main example.com
    python3 -m engine.main example.com --stealth --proxy
    python3 -m engine.main --report
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.state import TargetState, StateManager
from engine.scorer import Scorer
from engine.decision import DecisionEngine
from engine.context import ContextBuilder
from engine.output import OutputGenerator
from engine.js_intel import JSIntelligence


class Shadow:
    """Main SHADOW engine controller"""
    
    VERSION = "6.0.0"
    BANNER = """
    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗    ██╗   ██╗ ██████╗ 
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║    ██║   ██║██╔════╝ 
    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║    ██║   ██║███████╗ 
    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║    ╚██╗ ██╔╝██╔═══██╗
    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝     ╚████╔╝ ╚██████╔╝
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝       ╚═══╝   ╚═════╝ 
                    Intelligence-Driven Bug Bounty Engine
    """
    
    def __init__(self, script_dir: str = None):
        if script_dir is None:
            script_dir = str(Path(__file__).parent.parent)
        
        self.script_dir = Path(script_dir)
        self.context_builder = ContextBuilder(script_dir)
        self.context = None
        self.state_manager = None
        self.decision_engine = None
        self.output_generator = None
        self.scorer = Scorer()
    
    def init(self, target: str = None, **kwargs):
        """Initialize the engine for a target"""
        if target:
            self.context = self.context_builder.build_for_target(target, **kwargs)
        else:
            self.context = self.context_builder.build(**kwargs)
        
        self.state_manager = StateManager(str(self.context.output_dir))
        self.decision_engine = DecisionEngine(
            self.state_manager, 
            str(self.script_dir)
        )
        self.output_generator = OutputGenerator(
            self.state_manager,
            self.context.output_dir
        )
        
        return self
    
    def run(self, target: str) -> TargetState:
        """Run the complete pipeline on a target"""
        print(self.BANNER)
        print(f"[*] Target: {target}")
        print(f"[*] Session: {self.context.session_id}")
        print(f"[*] Output: {self.context.base_path}")
        print("")
        
        if self.context.stealth_mode:
            print("[!] STEALTH MODE ENABLED")
            print("")
        
        # Run decision-driven pipeline
        state = self.decision_engine.run_pipeline(target, self.context.base_path)
        
        # Calculate final score
        score = self.scorer.calculate(state)
        
        print("")
        print("=" * 70)
        print("                         RESULTS                                     ")
        print("=" * 70)
        print(score.summary())
        print("")
        print(state.summary())
        
        return state
    
    def analyze_js(self, target: str = None) -> None:
        """Run JS intelligence analysis"""
        if target:
            js_dir = Path(self.context.base_path) / "js" / "files"
        else:
            # Analyze all targets
            js_dir = self.context.logs_dir
        
        if not js_dir.exists():
            print(f"[!] JS directory not found: {js_dir}")
            return
        
        print("[*] Running JavaScript Intelligence Analysis...")
        
        js_intel = JSIntelligence()
        analysis = js_intel.analyze_directory(js_dir)
        
        print(js_intel.generate_report())
    
    def show_decisions(self, target: str) -> None:
        """Show what decisions the engine would make"""
        state = self.state_manager.load(target)
        if not state:
            print(f"[!] No state found for: {target}")
            return
        
        print(f"[*] Decisions for: {target}")
        print(f"[*] Current phase: {state.phase.value}")
        print(f"[*] Current score: {state.score}")
        print("")
        
        decisions = self.decision_engine.get_next_actions(state)
        
        for decision in decisions:
            icon = {
                "run_module": "🟢",
                "skip_module": "⏭️",
                "run_tool": "🔧",
                "pause": "⏸️",
                "stop": "🛑",
                "manual": "👤",
                "prioritize": "⬆️"
            }.get(decision.type.value, "•")
            
            print(f"{icon} [{decision.type.value.upper()}] {decision.action}")
            print(f"   Reason: {decision.reason}")
            print("")
    
    def generate_report(self, limit: int = 20) -> None:
        """Generate top targets report"""
        print(f"[*] Generating Top {limit} Targets Report...")
        
        paths = self.output_generator.save_reports(limit)
        
        print(f"[+] Reports saved:")
        for fmt, path in paths.items():
            print(f"    {fmt}: {path}")
        
        # Also print to console
        print("")
        print(self.output_generator.generate_top_targets_report(limit))
    
    def list_targets(self) -> None:
        """List all scanned targets"""
        states = self.state_manager.list_all()
        
        if not states:
            print("[!] No targets found")
            return
        
        print(f"[*] Found {len(states)} targets:")
        print("")
        print(f"{'Domain':<40} {'Score':<8} {'Priority':<10} {'Phase':<15}")
        print("-" * 75)
        
        for state in sorted(states, key=lambda s: s.score, reverse=True):
            print(f"{state.domain:<40} {state.score:<8} {state.priority:<10} {state.phase.value:<15}")
    
    def show_state(self, target: str) -> None:
        """Show detailed state for a target"""
        state = self.state_manager.load(target)
        if not state:
            print(f"[!] No state found for: {target}")
            return
        
        print(state.summary())
        print("")
        
        # Show score breakdown
        score = self.scorer.calculate(state)
        print(score.summary())


def main():
    parser = argparse.ArgumentParser(
        description="SHADOW v6 - Intelligence-Driven Bug Bounty Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s example.com                    # Full scan
    %(prog)s example.com --stealth          # Stealth mode
    %(prog)s example.com --proxy            # With Burp proxy
    %(prog)s --report                       # Generate reports
    %(prog)s --list                         # List all targets
    %(prog)s --state example.com            # Show target state
    %(prog)s --decisions example.com        # Show what would run
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target domain to scan")
    
    # Mode options
    parser.add_argument("--report", action="store_true", help="Generate top targets report")
    parser.add_argument("--list", action="store_true", help="List all scanned targets")
    parser.add_argument("--state", metavar="DOMAIN", help="Show state for a target")
    parser.add_argument("--decisions", metavar="DOMAIN", help="Show decisions for a target")
    parser.add_argument("--js", action="store_true", help="Run JS intelligence analysis")
    
    # Scan options
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--proxy", action="store_true", help="Enable Burp proxy")
    parser.add_argument("--proxy-url", default="http://127.0.0.1:8080", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    
    # Output options
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--limit", type=int, default=20, help="Number of targets in report")
    
    args = parser.parse_args()
    
    # Initialize Shadow
    shadow = Shadow()
    
    # Handle different modes
    if args.report:
        shadow.init(output_dir=args.output)
        shadow.generate_report(args.limit)
    
    elif args.list:
        shadow.init(output_dir=args.output)
        shadow.list_targets()
    
    elif args.state:
        shadow.init(output_dir=args.output)
        shadow.show_state(args.state)
    
    elif args.decisions:
        shadow.init(output_dir=args.output)
        shadow.show_decisions(args.decisions)
    
    elif args.js:
        shadow.init(target=args.target, output_dir=args.output)
        shadow.analyze_js(args.target)
    
    elif args.target:
        shadow.init(
            target=args.target,
            output_dir=args.output,
            verbose=args.verbose,
            debug=args.debug,
            stealth=args.stealth,
            proxy=args.proxy,
            proxy_url=args.proxy_url
        )
        shadow.run(args.target)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

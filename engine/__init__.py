"""
SHADOW v6 - Intelligence-Driven Bug Bounty Decision Engine

This engine transforms SHADOW from a tool orchestrator into a decision-making system.
Bash executes tools. Python makes decisions.
"""

__version__ = "6.0.0"
__author__ = "SHADOW Team"

from .state import TargetState, StateManager
from .scorer import Scorer, Score
from .decision import DecisionEngine, Decision
from .context import Context, ContextBuilder
from .schemas import (
    ModuleOutput,
    IntelOutput,
    SubdomainsOutput,
    DNSOutput,
    HTTPOutput,
    ContentOutput,
    JSOutput,
    ParamsOutput,
    VulnOutput,
    PipelineResult
)
from .runner import ModuleRunner, ModuleOrchestrator

__all__ = [
    # State
    'TargetState',
    'StateManager', 
    # Scoring
    'Scorer',
    'Score',
    # Decision
    'DecisionEngine',
    'Decision',
    # Context
    'Context',
    'ContextBuilder',
    # Schemas
    'ModuleOutput',
    'IntelOutput',
    'SubdomainsOutput',
    'DNSOutput',
    'HTTPOutput',
    'ContentOutput',
    'JSOutput',
    'ParamsOutput',
    'VulnOutput',
    'PipelineResult',
    # Runner
    'ModuleRunner',
    'ModuleOrchestrator'
]

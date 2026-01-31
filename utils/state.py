#!/usr/bin/env python3
"""
SHADOW - State Management

Resume tokens, lockfiles, and state persistence.
"""

import os
import json
import fcntl
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict


# ═══════════════════════════════════════════════════════════════════════════════
# STATE DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ResumeToken:
    """Token to resume interrupted scans"""
    domain: str
    started_at: str
    last_update: str
    phase: str  # subdomains, dns, http, crawl, nuclei
    phase_progress: int  # 0-100
    completed_phases: List[str] = field(default_factory=list)
    error_count: int = 0
    last_error: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ResumeToken':
        return cls(**data)
    
    @classmethod
    def new(cls, domain: str) -> 'ResumeToken':
        now = datetime.utcnow().isoformat()
        return cls(
            domain=domain,
            started_at=now,
            last_update=now,
            phase="init",
            phase_progress=0,
            completed_phases=[],
            error_count=0,
            last_error=""
        )


@dataclass
class ScanState:
    """Complete state of a scan"""
    token: ResumeToken
    stats: Dict[str, int] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "token": self.token.to_dict(),
            "stats": self.stats,
            "options": self.options
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanState':
        return cls(
            token=ResumeToken.from_dict(data["token"]),
            stats=data.get("stats", {}),
            options=data.get("options", {})
        )


# ═══════════════════════════════════════════════════════════════════════════════
# STATE MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class StateManager:
    """
    Manages scan state with file locking for safe concurrent access.
    
    Usage:
        with StateManager(output_dir) as state:
            state.start("example.com")
            state.update_phase("subdomains", 50)
            state.complete_phase("subdomains")
    """
    
    STATE_FILE = "shadow_state.json"
    LOCK_FILE = "shadow.lock"
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.state_path = self.output_dir / self.STATE_FILE
        self.lock_path = self.output_dir / self.LOCK_FILE
        
        self._lock_fd: Optional[int] = None
        self._state: Optional[ScanState] = None
    
    def __enter__(self) -> 'StateManager':
        self._acquire_lock()
        self._load_state()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._save_state()
        self._release_lock()
        return False
    
    def _acquire_lock(self):
        """Acquire exclusive file lock"""
        self._lock_fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._lock_fd)
            raise RuntimeError(f"Another scan is running in {self.output_dir}")
    
    def _release_lock(self):
        """Release file lock"""
        if self._lock_fd is not None:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None
            
            # Remove lock file
            try:
                self.lock_path.unlink()
            except:
                pass
    
    def _load_state(self):
        """Load state from file"""
        if self.state_path.exists():
            try:
                with open(self.state_path) as f:
                    data = json.load(f)
                self._state = ScanState.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                self._state = None
        else:
            self._state = None
    
    def _save_state(self):
        """Save state to file"""
        if self._state:
            self._state.token.last_update = datetime.utcnow().isoformat()
            with open(self.state_path, 'w') as f:
                json.dump(self._state.to_dict(), f, indent=2)
    
    # ─────────────────────────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────────────────────────
    
    def start(self, domain: str, options: Dict[str, Any] = None) -> ResumeToken:
        """Start a new scan or resume existing"""
        if self._state and self._state.token.domain == domain:
            # Resume existing
            return self._state.token
        
        # New scan
        self._state = ScanState(
            token=ResumeToken.new(domain),
            options=options or {}
        )
        self._save_state()
        return self._state.token
    
    def can_resume(self, domain: str) -> bool:
        """Check if there's a resumable state for domain"""
        return (
            self._state is not None and
            self._state.token.domain == domain and
            self._state.token.phase != "complete"
        )
    
    def get_resume_point(self) -> Optional[str]:
        """Get the phase to resume from"""
        if not self._state:
            return None
        
        phases = ["subdomains", "dns", "http", "crawl", "nuclei"]
        completed = set(self._state.token.completed_phases)
        
        for phase in phases:
            if phase not in completed:
                return phase
        
        return None
    
    def update_phase(self, phase: str, progress: int):
        """Update current phase progress (0-100)"""
        if self._state:
            self._state.token.phase = phase
            self._state.token.phase_progress = progress
            self._save_state()
    
    def complete_phase(self, phase: str, stats: Dict[str, int] = None):
        """Mark a phase as complete"""
        if self._state:
            if phase not in self._state.token.completed_phases:
                self._state.token.completed_phases.append(phase)
            self._state.token.phase_progress = 100
            
            if stats:
                self._state.stats.update(stats)
            
            self._save_state()
    
    def record_error(self, error: str):
        """Record an error"""
        if self._state:
            self._state.token.error_count += 1
            self._state.token.last_error = error
            self._save_state()
    
    def complete(self):
        """Mark scan as complete"""
        if self._state:
            self._state.token.phase = "complete"
            self._state.token.phase_progress = 100
            self._save_state()
    
    def clear(self):
        """Clear state (for fresh start)"""
        self._state = None
        if self.state_path.exists():
            self.state_path.unlink()
    
    @property
    def token(self) -> Optional[ResumeToken]:
        return self._state.token if self._state else None
    
    @property
    def stats(self) -> Dict[str, int]:
        return self._state.stats if self._state else {}


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def get_state_hash(data: Dict) -> str:
    """Generate hash of state for change detection"""
    serialized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def has_running_scan(output_dir: str) -> bool:
    """Check if a scan is currently running"""
    lock_path = Path(output_dir) / StateManager.LOCK_FILE
    
    if not lock_path.exists():
        return False
    
    try:
        fd = os.open(str(lock_path), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False  # Lock acquired = no running scan
        except BlockingIOError:
            return True  # Lock held = scan running
        finally:
            os.close(fd)
    except:
        return False


def get_resume_info(output_dir: str) -> Optional[Dict]:
    """Get resume info without locking"""
    state_path = Path(output_dir) / StateManager.STATE_FILE
    
    if not state_path.exists():
        return None
    
    try:
        with open(state_path) as f:
            return json.load(f)
    except:
        return None

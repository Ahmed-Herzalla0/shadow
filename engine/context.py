"""
SHADOW v6 - Context Manager

Manages execution context, configuration, and environment.
Provides unified access to settings and runtime information.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
import configparser


@dataclass
class RateConfig:
    """Rate limiting configuration"""
    global_threads: int = 50
    global_timeout: int = 10
    global_retries: int = 2
    
    # Rate profiles
    stealth_rate: int = 10
    stealth_delay: float = 2.0
    stealth_threads: int = 5
    
    normal_rate: int = 100
    normal_delay: float = 0.5
    normal_threads: int = 30
    
    aggressive_rate: int = 500
    aggressive_delay: float = 0.0
    aggressive_threads: int = 100
    
    # Noise detection
    noise_pause_time: int = 60
    noise_max_403: int = 10
    noise_max_429: int = 3
    noise_max_timeout: int = 5


@dataclass
class ScopeConfig:
    """Scope configuration"""
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    excluded_extensions: List[str] = field(default_factory=lambda: [
        "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "eot"
    ])


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    enabled: bool = False
    url: str = "http://127.0.0.1:8080"
    burp_project: Optional[str] = None


@dataclass
class Context:
    """
    Complete execution context for SHADOW.
    This is passed to all modules and provides unified access to configuration.
    """
    # Paths
    script_dir: Path
    output_dir: Path
    logs_dir: Path
    
    # Target info
    target: str = ""
    base_path: str = ""
    
    # Configurations
    rate: RateConfig = field(default_factory=RateConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    
    # Runtime state
    verbose: bool = False
    debug: bool = False
    dry_run: bool = False
    stealth_mode: bool = False
    
    # Session info
    session_id: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Custom settings
    settings: Dict[str, Any] = field(default_factory=dict)
    
    def get_rate_profile(self) -> Dict[str, Any]:
        """Get current rate profile based on stealth mode"""
        if self.stealth_mode:
            return {
                "rate": self.rate.stealth_rate,
                "delay": self.rate.stealth_delay,
                "threads": self.rate.stealth_threads
            }
        else:
            return {
                "rate": self.rate.normal_rate,
                "delay": self.rate.normal_delay,
                "threads": self.rate.normal_threads
            }
    
    def get_proxy_args(self, tool: str) -> str:
        """Get proxy arguments for a specific tool"""
        if not self.proxy.enabled:
            return ""
        
        # Tool-specific proxy args
        proxy_args = {
            "nuclei": f"-proxy {self.proxy.url}",
            "httpx": f"-proxy {self.proxy.url}",
            "katana": f"-proxy {self.proxy.url}",
            "ffuf": f"-x {self.proxy.url}",
            "dalfox": f"--proxy {self.proxy.url}",
            "sqlmap": f"--proxy={self.proxy.url}",
            "curl": f"-x {self.proxy.url}",
        }
        return proxy_args.get(tool, "")
    
    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in scope"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check out of scope first
        for pattern in self.scope.out_of_scope:
            if pattern in domain:
                return False
        
        # Check in scope
        if not self.scope.in_scope:
            return True  # If no scope defined, everything is in scope
        
        for pattern in self.scope.in_scope:
            if pattern in domain:
                return True
        
        return False
    
    def should_exclude_url(self, url: str) -> bool:
        """Check if URL should be excluded based on extension"""
        ext = url.split(".")[-1].lower().split("?")[0]
        return ext in self.scope.excluded_extensions
    
    def to_env(self) -> Dict[str, str]:
        """Convert context to environment variables for Bash modules"""
        rate = self.get_rate_profile()
        return {
            "SHADOW_TARGET": self.target,
            "SHADOW_BASE": self.base_path,
            "SHADOW_SESSION": self.session_id,
            "SCRIPT_DIR": str(self.script_dir),
            "OUTPUT_DIR": str(self.output_dir),
            "VERBOSE": "1" if self.verbose else "0",
            "DEBUG": "1" if self.debug else "0",
            "STEALTH_MODE": "true" if self.stealth_mode else "false",
            "ENABLE_PROXY": "true" if self.proxy.enabled else "false",
            "PROXY_URL": self.proxy.url,
            "RATE_LIMIT": str(rate["rate"]),
            "THREADS": str(rate["threads"]),
            "DELAY": str(rate["delay"]),
            "NOISE_PAUSE_TIME": str(self.rate.noise_pause_time),
            "NOISE_MAX_429": str(self.rate.noise_max_429),
            "NOISE_MAX_403": str(self.rate.noise_max_403),
        }


class ContextBuilder:
    """
    Builds execution context from various sources:
    - Config files
    - Environment variables
    - Command line arguments
    """
    
    def __init__(self, script_dir: str):
        self.script_dir = Path(script_dir)
        self.config_dir = self.script_dir / "config"
    
    def load_rate_config(self) -> RateConfig:
        """Load rate configuration from rate.conf"""
        config = RateConfig()
        rate_file = self.config_dir / "rate.conf"
        
        if rate_file.exists():
            with open(rate_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip().lower()
                        value = value.strip().strip('"')
                        
                        # Map config keys to RateConfig attributes
                        mapping = {
                            "global_threads": ("global_threads", int),
                            "global_timeout": ("global_timeout", int),
                            "stealth_rate": ("stealth_rate", int),
                            "stealth_delay": ("stealth_delay", float),
                            "stealth_threads": ("stealth_threads", int),
                            "normal_rate": ("normal_rate", int),
                            "normal_delay": ("normal_delay", float),
                            "normal_threads": ("normal_threads", int),
                            "noise_pause_time": ("noise_pause_time", int),
                            "noise_max_403": ("noise_max_403", int),
                            "noise_max_429": ("noise_max_429", int),
                            "noise_max_timeout": ("noise_max_timeout", int),
                        }
                        
                        if key in mapping:
                            attr, converter = mapping[key]
                            try:
                                setattr(config, attr, converter(value))
                            except ValueError:
                                pass
        
        return config
    
    def load_scope_config(self) -> ScopeConfig:
        """Load scope configuration from scope.conf"""
        config = ScopeConfig()
        scope_file = self.config_dir / "scope.conf"
        
        if scope_file.exists():
            section = None
            with open(scope_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    if line.startswith("[") and line.endswith("]"):
                        section = line[1:-1].lower()
                    elif section == "in_scope":
                        config.in_scope.append(line)
                    elif section == "out_of_scope":
                        config.out_of_scope.append(line)
                    elif section == "excluded_extensions":
                        config.excluded_extensions.append(line)
        
        return config
    
    def load_env_file(self) -> Dict[str, str]:
        """Load .env file if exists"""
        env = {}
        env_file = self.script_dir / ".env"
        
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        env[key.strip()] = value.strip().strip('"')
        
        return env
    
    def build(
        self,
        target: str = "",
        output_dir: Optional[str] = None,
        verbose: bool = False,
        debug: bool = False,
        stealth: bool = False,
        proxy: bool = False,
        proxy_url: str = "http://127.0.0.1:8080"
    ) -> Context:
        """Build complete context"""
        
        # Load configurations
        rate_config = self.load_rate_config()
        scope_config = self.load_scope_config()
        env_vars = self.load_env_file()
        
        # Determine output directory
        if output_dir:
            out_dir = Path(output_dir)
        else:
            out_dir = self.script_dir / "output"
        
        # Create context
        ctx = Context(
            script_dir=self.script_dir,
            output_dir=out_dir,
            logs_dir=out_dir / "logs",
            target=target,
            rate=rate_config,
            scope=scope_config,
            verbose=verbose,
            debug=debug,
            stealth_mode=stealth,
            proxy=ProxyConfig(
                enabled=proxy,
                url=proxy_url
            )
        )
        
        # Apply environment overrides
        if "STEALTH_MODE" in env_vars:
            ctx.stealth_mode = env_vars["STEALTH_MODE"].lower() == "true"
        if "ENABLE_PROXY" in env_vars:
            ctx.proxy.enabled = env_vars["ENABLE_PROXY"].lower() == "true"
        if "PROXY_URL" in env_vars:
            ctx.proxy.url = env_vars["PROXY_URL"]
        
        # Create directories
        ctx.output_dir.mkdir(parents=True, exist_ok=True)
        ctx.logs_dir.mkdir(parents=True, exist_ok=True)
        
        return ctx
    
    def build_for_target(self, target: str, **kwargs) -> Context:
        """Build context for a specific target"""
        ctx = self.build(target=target, **kwargs)
        
        # Create target-specific paths
        safe_target = target.replace(".", "_").replace("/", "_")
        ctx.base_path = str(ctx.logs_dir / f"{safe_target}_{ctx.session_id}")
        Path(ctx.base_path).mkdir(parents=True, exist_ok=True)
        
        return ctx

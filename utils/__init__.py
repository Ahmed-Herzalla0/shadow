#!/usr/bin/env python3
"""
SHADOW - Logging Utilities

Unified logging with proper levels and formatting.
"""

import logging
import sys
from typing import Optional
from pathlib import Path
from datetime import datetime


# ═══════════════════════════════════════════════════════════════════════════════
# LOG LEVELS
# ═══════════════════════════════════════════════════════════════════════════════

# Custom TRACE level for very detailed debugging
TRACE = 5
logging.addLevelName(TRACE, "TRACE")


class ShadowLogger(logging.Logger):
    """Custom logger with TRACE level support"""
    
    def trace(self, msg, *args, **kwargs):
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)


# Register custom logger class
logging.setLoggerClass(ShadowLogger)


# ═══════════════════════════════════════════════════════════════════════════════
# FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════════

class ColoredFormatter(logging.Formatter):
    """Colored console output"""
    
    COLORS = {
        'TRACE': '\033[0;37m',      # Gray
        'DEBUG': '\033[0;36m',      # Cyan
        'INFO': '\033[0;32m',       # Green
        'WARNING': '\033[0;33m',    # Yellow
        'ERROR': '\033[0;31m',      # Red
        'CRITICAL': '\033[1;31m',   # Bold Red
    }
    RESET = '\033[0m'
    
    ICONS = {
        'TRACE': '·',
        'DEBUG': '○',
        'INFO': '✓',
        'WARNING': '!',
        'ERROR': '✗',
        'CRITICAL': '✗✗',
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        icon = self.ICONS.get(record.levelname, '')
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Build message
        if record.levelname in ('ERROR', 'CRITICAL'):
            formatted = f"{color}[{icon}] {record.levelname}: {record.getMessage()}{self.RESET}"
        else:
            formatted = f"{color}[{icon}] {record.getMessage()}{self.RESET}"
        
        return formatted


class JSONFormatter(logging.Formatter):
    """JSON output for structured logging"""
    
    def format(self, record):
        import json
        
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)


class FileFormatter(logging.Formatter):
    """Plain text formatter for file output"""
    
    def __init__(self):
        super().__init__(
            fmt='%(asctime)s [%(levelname)s] %(name)s.%(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGER SETUP
# ═══════════════════════════════════════════════════════════════════════════════

_logger: Optional[ShadowLogger] = None


def get_logger(name: str = "shadow") -> ShadowLogger:
    """Get or create the SHADOW logger"""
    global _logger
    
    if _logger is None:
        _logger = logging.getLogger(name)
        _logger.__class__ = ShadowLogger
        
        # Default to INFO level
        _logger.setLevel(logging.INFO)
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(ColoredFormatter())
        _logger.addHandler(console_handler)
    
    return _logger


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_output: bool = False
) -> ShadowLogger:
    """
    Configure logging with specified options.
    
    Args:
        level: Log level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        json_output: Use JSON format for console output
    
    Returns:
        Configured logger instance
    """
    logger = get_logger()
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Set level
    if level.upper() == "TRACE":
        logger.setLevel(TRACE)
    else:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    if json_output:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(FileFormatter())
        logger.addHandler(file_handler)
    
    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def trace(msg: str, *args, **kwargs):
    """Log at TRACE level"""
    get_logger().log(TRACE, msg, *args, **kwargs)


def debug(msg: str, *args, **kwargs):
    """Log at DEBUG level"""
    get_logger().debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs):
    """Log at INFO level"""
    get_logger().info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs):
    """Log at WARNING level"""
    get_logger().warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs):
    """Log at ERROR level"""
    get_logger().error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs):
    """Log at CRITICAL level"""
    get_logger().critical(msg, *args, **kwargs)


# ═══════════════════════════════════════════════════════════════════════════════
# PROGRESS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

class ProgressBar:
    """Simple progress bar for terminal output"""
    
    def __init__(self, total: int, desc: str = "", width: int = 40):
        self.total = total
        self.desc = desc
        self.width = width
        self.current = 0
    
    def update(self, n: int = 1):
        """Update progress by n steps"""
        self.current = min(self.current + n, self.total)
        self._render()
    
    def _render(self):
        if self.total == 0:
            pct = 100
        else:
            pct = int(100 * self.current / self.total)
        
        filled = int(self.width * self.current / self.total) if self.total > 0 else self.width
        bar = '█' * filled + '░' * (self.width - filled)
        
        sys.stderr.write(f'\r{self.desc} |{bar}| {pct}% ({self.current}/{self.total})')
        sys.stderr.flush()
    
    def finish(self):
        """Complete the progress bar"""
        self.current = self.total
        self._render()
        sys.stderr.write('\n')


def progress_bar(total: int, desc: str = "") -> ProgressBar:
    """Create a progress bar"""
    return ProgressBar(total, desc)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def section(title: str, width: int = 60):
    """Print a section header"""
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def subsection(title: str, width: int = 40):
    """Print a subsection header"""
    print()
    print("-" * width)
    print(f"  {title}")
    print("-" * width)

#!/usr/bin/env python3
"""
SHADOW - Structured Logging

Centralized JSON logging with --debug verbosity control.

Features:
- JSON-formatted log output for machine parsing
- Colored console output for humans
- File logging with rotation
- TRACE level for very detailed debugging
- Thread-safe operation

Usage:
    from utils.logging import setup_logging, get_logger
    
    setup_logging(level="DEBUG", json_output=True)
    log = get_logger()
    log.info("Starting scan", extra={"target": "example.com"})

Author: SHADOW Team
License: MIT
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM LOG LEVELS
# ═══════════════════════════════════════════════════════════════════════════════

TRACE = 5
logging.addLevelName(TRACE, "TRACE")


class ShadowLogger(logging.Logger):
    """Custom logger with TRACE level and structured extras"""

    def trace(self, msg: str, *args, **kwargs) -> None:
        """Log at TRACE level (very detailed debugging)"""
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)

    def log_event(
        self,
        event: str,
        level: int = logging.INFO,
        **data: Any,
    ) -> None:
        """Log a structured event with additional data"""
        extra = {"event": event, "data": data}
        self.log(level, f"{event}: {json.dumps(data)}", extra=extra)


# Register custom logger class
logging.setLoggerClass(ShadowLogger)


# ═══════════════════════════════════════════════════════════════════════════════
# FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════════

class ColoredFormatter(logging.Formatter):
    """Console formatter with ANSI colors"""

    COLORS = {
        "TRACE": "\033[0;37m",     # Gray
        "DEBUG": "\033[0;36m",     # Cyan
        "INFO": "\033[0;32m",      # Green
        "WARNING": "\033[0;33m",   # Yellow
        "ERROR": "\033[0;31m",     # Red
        "CRITICAL": "\033[1;31m",  # Bold Red
    }
    RESET = "\033[0m"

    ICONS = {
        "TRACE": "·",
        "DEBUG": "○",
        "INFO": "✓",
        "WARNING": "!",
        "ERROR": "✗",
        "CRITICAL": "✗✗",
    }

    def __init__(self, include_timestamp: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        icon = self.ICONS.get(record.levelname, "")

        parts = []

        if self.include_timestamp:
            timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            parts.append(f"\033[0;90m{timestamp}\033[0m")  # Gray timestamp

        parts.append(f"{color}[{icon}]")

        if record.levelname in ("ERROR", "CRITICAL"):
            parts.append(f"{record.levelname}:")

        parts.append(f"{record.getMessage()}{self.RESET}")

        return " ".join(parts)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""

    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add thread info for debugging
        log_entry["thread"] = threading.current_thread().name

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if self.include_extra:
            for key, value in record.__dict__.items():
                if key not in (
                    "name", "msg", "args", "created", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs",
                    "pathname", "process", "processName", "relativeCreated",
                    "stack_info", "exc_info", "exc_text", "thread", "threadName",
                    "message", "asctime",
                ):
                    try:
                        json.dumps(value)  # Check if serializable
                        log_entry[key] = value
                    except (TypeError, ValueError):
                        log_entry[key] = str(value)

        return json.dumps(log_entry, separators=(",", ":"))


class FileFormatter(logging.Formatter):
    """Plain text formatter for file logging"""

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(name)s.%(funcName)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

_logger: Optional[ShadowLogger] = None
_lock = threading.Lock()


def get_logger(name: str = "shadow") -> ShadowLogger:
    """
    Get the SHADOW logger instance.
    
    Thread-safe, returns singleton logger.
    """
    global _logger

    with _lock:
        if _logger is None:
            _logger = logging.getLogger(name)  # type: ignore
            _logger.__class__ = ShadowLogger

            # Default configuration
            _logger.setLevel(logging.INFO)

            # Console handler with colors (only if not already configured)
            if not _logger.handlers:
                console = logging.StreamHandler(sys.stderr)
                console.setFormatter(ColoredFormatter())
                _logger.addHandler(console)

    return _logger  # type: ignore


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    json_output: bool = False,
    include_timestamp: bool = True,
) -> ShadowLogger:
    """
    Configure logging with specified options.
    
    Args:
        level: Log level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        json_output: Use JSON format for console output
        include_timestamp: Include timestamps in console output
    
    Returns:
        Configured ShadowLogger instance
    
    Example:
        setup_logging(level="DEBUG", json_output=True)
        log = get_logger()
        log.info("Hello")
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
    console = logging.StreamHandler(sys.stderr)
    if json_output:
        console.setFormatter(JSONFormatter())
    else:
        console.setFormatter(ColoredFormatter(include_timestamp=include_timestamp))
    logger.addHandler(console)

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

def trace(msg: str, *args, **kwargs) -> None:
    """Log at TRACE level"""
    get_logger().log(TRACE, msg, *args, **kwargs)


def debug(msg: str, *args, **kwargs) -> None:
    """Log at DEBUG level"""
    get_logger().debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs) -> None:
    """Log at INFO level"""
    get_logger().info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs) -> None:
    """Log at WARNING level"""
    get_logger().warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs) -> None:
    """Log at ERROR level"""
    get_logger().error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs) -> None:
    """Log at CRITICAL level"""
    get_logger().critical(msg, *args, **kwargs)


def log_event(event: str, **data: Any) -> None:
    """Log a structured event"""
    get_logger().log_event(event, **data)


# ═══════════════════════════════════════════════════════════════════════════════
# CONTEXT MANAGERS
# ═══════════════════════════════════════════════════════════════════════════════

class LogContext:
    """Context manager for scoped logging with timing"""

    def __init__(self, operation: str, level: int = logging.INFO):
        self.operation = operation
        self.level = level
        self.start_time: float = 0
        self.log = get_logger()

    def __enter__(self) -> LogContext:
        import time
        self.start_time = time.time()
        self.log.log(self.level, f"Starting: {self.operation}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        import time
        duration = time.time() - self.start_time

        if exc_type:
            self.log.error(
                f"Failed: {self.operation} ({duration:.2f}s) - {exc_val}"
            )
        else:
            self.log.log(
                self.level,
                f"Completed: {self.operation} ({duration:.2f}s)"
            )

        return False  # Don't suppress exceptions


def log_context(operation: str, level: int = logging.INFO) -> LogContext:
    """Create a logging context manager"""
    return LogContext(operation, level)

#!/usr/bin/env python3
"""
SHADOW - Input Validation and Security

Prevent command injection and validate all inputs.
"""

import re
import shlex
from typing import List, Optional
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

# RFC 1123 compliant domain pattern
DOMAIN_PATTERN = re.compile(
    r'^(?=.{1,253}$)'  # Total length
    r'(?!-)'  # Cannot start with hyphen
    r'[a-zA-Z0-9-]{1,63}'  # First label
    r'(?:\.[a-zA-Z0-9-]{1,63})*'  # Additional labels
    r'(?<!-)$'  # Cannot end with hyphen
)

# Dangerous shell characters
SHELL_DANGEROUS = set(';&|`$(){}[]<>\\!#*?~')


class ValidationError(Exception):
    """Input validation failed"""
    pass


def validate_domain(domain: str) -> str:
    """
    Validate and sanitize a domain name.
    
    Args:
        domain: Domain to validate
        
    Returns:
        Sanitized domain
        
    Raises:
        ValidationError: If domain is invalid or contains dangerous characters
    """
    if not domain:
        raise ValidationError("Domain cannot be empty")
    
    # Strip whitespace
    domain = domain.strip().lower()
    
    # Check for shell dangerous characters
    if any(c in domain for c in SHELL_DANGEROUS):
        raise ValidationError(f"Domain contains dangerous characters: {domain}")
    
    # Check for newlines/control characters
    if any(ord(c) < 32 for c in domain):
        raise ValidationError("Domain contains control characters")
    
    # Validate format
    if not DOMAIN_PATTERN.match(domain):
        raise ValidationError(f"Invalid domain format: {domain}")
    
    # Check for suspicious patterns
    if '..' in domain:
        raise ValidationError("Domain contains '..'")
    
    return domain


def validate_domains(domains: List[str]) -> List[str]:
    """Validate a list of domains, returning only valid ones"""
    valid = []
    for domain in domains:
        try:
            valid.append(validate_domain(domain))
        except ValidationError:
            continue
    return valid


# ═══════════════════════════════════════════════════════════════════════════════
# URL VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def validate_url(url: str) -> str:
    """
    Validate and sanitize a URL.
    
    Args:
        url: URL to validate
        
    Returns:
        Sanitized URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    if not url:
        raise ValidationError("URL cannot be empty")
    
    url = url.strip()
    
    # Check for shell dangerous characters in unexpected places
    if any(c in url for c in ';|`$'):
        raise ValidationError(f"URL contains dangerous characters: {url}")
    
    # Parse and validate
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValidationError(f"Cannot parse URL: {url}")
    
    # Must have scheme and netloc
    if parsed.scheme not in ('http', 'https'):
        raise ValidationError(f"Invalid URL scheme: {parsed.scheme}")
    
    if not parsed.netloc:
        raise ValidationError(f"URL missing host: {url}")
    
    # Validate host portion
    host = parsed.netloc.split(':')[0]
    try:
        validate_domain(host)
    except ValidationError as e:
        raise ValidationError(f"Invalid URL host: {e}")
    
    return url


# ═══════════════════════════════════════════════════════════════════════════════
# PATH VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def validate_path(path: str) -> str:
    """
    Validate a URL path component.
    
    Args:
        path: Path to validate
        
    Returns:
        Sanitized path
    """
    if not path:
        return "/"
    
    path = path.strip()
    
    # Check for shell dangerous characters
    dangerous = set(';|`$(){}')
    if any(c in path for c in dangerous):
        raise ValidationError(f"Path contains dangerous characters")
    
    # Normalize
    if not path.startswith('/'):
        path = '/' + path
    
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# SQL VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

# Allowed SQL patterns for custom queries
ALLOWED_SQL_KEYWORDS = {
    'select', 'from', 'where', 'join', 'left', 'right', 'inner', 'outer',
    'on', 'and', 'or', 'not', 'in', 'like', 'between', 'is', 'null',
    'order', 'by', 'asc', 'desc', 'limit', 'offset', 'group', 'having',
    'distinct', 'count', 'sum', 'avg', 'min', 'max', 'as', 'case', 'when',
    'then', 'else', 'end', 'cast', 'coalesce', 'concat'
}

DANGEROUS_SQL_KEYWORDS = {
    'drop', 'delete', 'truncate', 'insert', 'update', 'alter', 'create',
    'grant', 'revoke', 'exec', 'execute', 'attach', 'detach', 'vacuum',
    'reindex', 'pragma'
}


def validate_sql_query(query: str) -> str:
    """
    Validate a custom SQL query (read-only).
    
    Args:
        query: SQL query to validate
        
    Returns:
        Query if valid
        
    Raises:
        ValidationError: If query contains dangerous patterns
    """
    if not query:
        raise ValidationError("Query cannot be empty")
    
    query_lower = query.lower().strip()
    
    # Must start with SELECT
    if not query_lower.startswith('select'):
        raise ValidationError("Only SELECT queries are allowed")
    
    # Check for dangerous keywords
    words = set(re.findall(r'\b[a-z]+\b', query_lower))
    dangerous = words & DANGEROUS_SQL_KEYWORDS
    
    if dangerous:
        raise ValidationError(f"Dangerous SQL keywords found: {dangerous}")
    
    # Check for comments
    if '--' in query or '/*' in query:
        raise ValidationError("SQL comments not allowed")
    
    # Check for multiple statements
    if ';' in query.rstrip(';'):
        raise ValidationError("Multiple SQL statements not allowed")
    
    return query


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND BUILDING
# ═══════════════════════════════════════════════════════════════════════════════

def build_safe_command(tool: str, args: List[str]) -> List[str]:
    """
    Build a safe command list for subprocess.
    
    Args:
        tool: Tool name (must be in PATH)
        args: Arguments (will be validated)
        
    Returns:
        Safe command list
    """
    # Validate tool name (alphanumeric + hyphen only)
    if not re.match(r'^[a-zA-Z0-9_-]+$', tool):
        raise ValidationError(f"Invalid tool name: {tool}")
    
    cmd = [tool]
    
    for arg in args:
        # Skip empty args
        if not arg:
            continue
        
        # Convert to string
        arg = str(arg)
        
        # Check for shell metacharacters in values
        # Allow some safe special chars in arguments
        if any(c in arg for c in ';&|`$()'):
            raise ValidationError(f"Dangerous characters in argument: {arg}")
        
        cmd.append(arg)
    
    return cmd


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe use.
    
    Args:
        filename: Original filename
        
    Returns:
        Safe filename
    """
    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')
    
    # Remove other dangerous characters
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Prevent empty or dot-only names
    if not filename or filename.startswith('.'):
        filename = 'file_' + filename
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Simple rate limiter for tool execution"""
    
    def __init__(self, requests_per_second: float = 10.0):
        self.rps = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request = 0.0
    
    def wait(self):
        """Wait if needed to respect rate limit"""
        import time
        
        now = time.time()
        elapsed = now - self.last_request
        
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        
        self.last_request = time.time()


# Default rate limiter
_default_limiter: Optional[RateLimiter] = None


def get_rate_limiter(rps: float = 10.0) -> RateLimiter:
    """Get or create default rate limiter"""
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = RateLimiter(rps)
    return _default_limiter

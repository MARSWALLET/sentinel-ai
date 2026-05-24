# ============================================
# SentinelAI - Validators
# ============================================
"""
Input validation utilities for scan targets.
Validates URLs, blocks internal IPs (unless self-hosted), and sanitizes inputs.
"""

import ipaddress
import logging
import re
from urllib.parse import urlparse

from config import settings

logger = logging.getLogger(__name__)

# Private IP ranges
PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private
    ipaddress.ip_network("172.16.0.0/12"),     # Private
    ipaddress.ip_network("192.168.0.0/16"),    # Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmark testing
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
]

# Allowed schemes
ALLOWED_SCHEMES = {"http", "https", "ssh", "git"}

# Dangerous characters in URLs
DANGEROUS_CHARS = re.compile(r"[<>'\"{}|\\\\^`\[\]]")


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL for scanning.
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "URL is required"
    
    # Check for dangerous characters
    if DANGEROUS_CHARS.search(url):
        return False, "URL contains dangerous characters"
    
    # Parse URL
    try:
        parsed = urlparse(url if "//" in url else f"http://{url}")
    except Exception:
        return False, "Invalid URL format"
    
    # Check scheme
    # Bug #31 fixed: if the URL has no scheme (e.g. 'example.com'), urlparse
    # sets parsed.scheme to '' which is falsy, silently skipping the allowlist
    # check. Treat a missing scheme as 'http' (already prepended above) and
    # explicitly reject if the resulting scheme is not in ALLOWED_SCHEMES.
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"URL scheme '{parsed.scheme}' is not allowed (must be one of: {', '.join(sorted(ALLOWED_SCHEMES))})"
    
    # Check hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must have a hostname"
    
    # Block localhost
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        if not settings.SELF_HOSTED_MODE:
            return False, "Scanning localhost is not allowed"
    
    # Check if it's an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        
        # Check private IPs
        if not settings.SELF_HOSTED_MODE:
            for network in PRIVATE_RANGES:
                if ip in network:
                    return False, f"Scanning private IP addresses is not allowed (found {ip})"
        
        # Check allowed internal IPs in self-hosted mode
        if settings.SELF_HOSTED_MODE:
            allowed = settings.ALLOWED_INTERNAL_IPS or []
            is_allowed = any(
                ip in ipaddress.ip_network(cidr, strict=False)
                for cidr in allowed
            )
            if not is_allowed:
                return False, f"IP {ip} is not in allowed ranges"
    except ValueError:
        # Not an IP, treat as domain - OK
        pass
    
    # Block common internal hostnames
    internal_hostnames = {"localhost", "host.docker.internal", "kubernetes.default"}
    if hostname.lower() in internal_hostnames:
        if not settings.SELF_HOSTED_MODE:
            return False, f"Scanning {hostname} is not allowed"
    
    return True, ""


def validate_github_url(url: str) -> tuple[bool, str]:
    """
    Validate a GitHub repository URL.
    
    Args:
        url: GitHub URL to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, "GitHub URL is required"
    
    # Basic URL validation
    valid, error = validate_url(url)
    if not valid:
        return False, error
    
    # Check it's a GitHub URL
    parsed = urlparse(url)
    if "github.com" not in parsed.netloc.lower():
        return False, "URL must be a github.com repository"
    
    # Check it looks like a repo URL
    path_parts = [p for p in parsed.path.split("/") if p]
    if len(path_parts) < 2:
        return False, "GitHub URL must be in format: https://github.com/owner/repo"
    
    return True, ""


def is_safe_filename(filename: str) -> tuple[bool, str]:
    """
    Check if a filename is safe.
    
    Args:
        filename: Filename to check
        
    Returns:
        Tuple of (is_safe, error_message)
    """
    if not filename:
        return False, "Filename is required"
    
    # Check for path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        return False, "Filename contains path traversal characters"
    
    # Check for null bytes
    if "\0" in filename:
        return False, "Filename contains null bytes"
    
    # Check for dangerous characters
    if re.search(r"[<>:\"|?*]", filename):
        return False, "Filename contains dangerous characters"
    
    # Check max length
    if len(filename) > 255:
        return False, "Filename too long"
    
    return True, ""


def sanitize_input(text: str, max_length: int = 10000) -> str:
    """
    Sanitize user input.
    
    Args:
        text: Input text
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Truncate
    text = text[:max_length]
    
    # Remove null bytes
    text = text.replace("\0", "")
    
    # Remove control characters except newlines and tabs
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch == "\r" or (ch.isprintable() or ch.isspace()))
    
    return text
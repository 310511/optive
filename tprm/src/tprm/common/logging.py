"""Structured logging with PII-scrubbing processor.

Usage:
    from tprm.common.logging import get_logger
    log = get_logger(__name__)
    log.info("block_processed", block_id=block.id, stage="pii")

NEVER pass raw entity text, block.text, or vault plaintext to any log call.
"""

from __future__ import annotations

import re
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor

# ── PII patterns to scrub from log output ─────────────────────────────────────
# These match common PII patterns that might accidentally slip into a log call.
# The scrubber replaces matches with [SCRUBBED:<PATTERN_NAME>].

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Email (must come before phone to avoid partial matches)
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    # IPv4 (must come before phone/SSN — dotted quads would otherwise match phone heuristic)
    ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")),
    # Credit card (4 groups of 4 digits)
    ("CREDIT_CARD", re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")),
    # SSN (xxx-xx-xxxx)
    ("SSN", re.compile(r"\b\d{3}[\-]\d{2}[\-]\d{4}\b")),
    # Phone (broad — after IP and SSN to reduce false positives)
    ("PHONE", re.compile(r"\b(?:\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]\d{3}[\s\-]\d{4}\b")),
    # API key patterns: AWS AKIA, GitHub ghp_, Slack xoxb-
    ("API_KEY", re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xoxb-[A-Za-z0-9\-]+)\b")),
    # PEM private key header
    ("PEM_KEY", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    # High-entropy strings (rough heuristic — 40+ chars of base64/hex)
    ("HIGH_ENTROPY", re.compile(r"[A-Za-z0-9+/=]{40,}")),
    # TPRM vault tokens (should not appear in logs either)
    ("VAULT_TOKEN", re.compile(r"<<[A-Z_]+_[0-9a-f]{8}>>")),
]


def _scrub_pii(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """structlog processor: replace PII patterns in all string values."""
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            scrubbed = value
            for name, pattern in _PII_PATTERNS:
                scrubbed = pattern.sub(f"[SCRUBBED:{name}]", scrubbed)
            event_dict[key] = scrubbed
        elif isinstance(value, dict):
            # Recurse one level for nested dicts (e.g. structured extras)
            event_dict[key] = {
                k: _scrub_value(v) for k, v in value.items()
            }
    return event_dict


def _scrub_value(value: Any) -> Any:
    """Scrub a single value if it's a string; return as-is otherwise."""
    if not isinstance(value, str):
        return value
    scrubbed = value
    for name, pattern in _PII_PATTERNS:
        scrubbed = pattern.sub(f"[SCRUBBED:{name}]", scrubbed)
    return scrubbed


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    """Configure structlog for the application.

    Call once at startup (e.g., in ``api/main.py`` or ``cli.py``).
    """
    shared_processors: list[Processor] = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        _scrub_pii,  # PII scrubber — must run before any renderer
    ]

    if json_logs:
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(__import__("logging"), level, 20)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a structlog bound logger for ``name``."""
    return structlog.get_logger(name)  # type: ignore[return-value]

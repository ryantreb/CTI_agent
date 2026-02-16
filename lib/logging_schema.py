#!/usr/bin/env python3
"""
JTIA Structured Logging Schema

Provides unified log entry creation and error classification
across all skills and MCP server interactions.
"""

from datetime import datetime, timezone

VALID_EVENT_TYPES = {"mcp_call", "enrichment", "analysis", "error", "metric", "skill_start", "skill_end", "health_check"}
VALID_SEVERITIES = {"info", "warn", "error", "critical"}


def create_log_entry(
    session_id: str,
    skill: str,
    event_type: str,
    severity: str,
    data: dict,
) -> dict:
    """Create a structured log entry conforming to JTIA schema."""
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError(f"Invalid event_type '{event_type}'. Must be one of: {VALID_EVENT_TYPES}")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'. Must be one of: {VALID_SEVERITIES}")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "skill": skill,
        "event_type": event_type,
        "severity": severity,
        "data": data,
    }


def classify_error(http_status: int, message: str) -> dict:
    """Classify an error by HTTP status code and message."""
    if http_status == 429 or (500 <= http_status <= 599):
        return {
            "class": "TRANSIENT",
            "recovery": "exponential_backoff",
            "max_retries": 3,
            "description": f"Transient error ({http_status}): {message}",
        }
    if http_status in (401, 403):
        return {
            "class": "AUTH",
            "recovery": "skip_server",
            "max_retries": 0,
            "description": f"Auth error ({http_status}): {message}",
        }
    if http_status == 404:
        return {
            "class": "NOT_FOUND",
            "recovery": "mark_refuted",
            "max_retries": 0,
            "description": f"Not found ({http_status}): {message}",
        }
    if http_status == 0 or http_status is None:
        return {
            "class": "UNAVAILABLE",
            "recovery": "skip_server",
            "max_retries": 0,
            "description": f"Server unavailable: {message}",
        }
    return {
        "class": "UNKNOWN",
        "recovery": "log_and_continue",
        "max_retries": 0,
        "description": f"Unclassified error ({http_status}): {message}",
    }

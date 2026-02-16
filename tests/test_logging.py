#!/usr/bin/env python3
"""Tests for structured logging."""

import json
import pytest
from datetime import datetime, timezone


class TestLogEntry:

    def test_create_log_entry(self):
        from lib.logging_schema import create_log_entry
        entry = create_log_entry(
            session_id="test-session",
            skill="enrich-iocs",
            event_type="mcp_call",
            severity="info",
            data={"mcp_server": "gti", "ioc_type": "hash"}
        )
        assert entry["session_id"] == "test-session"
        assert entry["skill"] == "enrich-iocs"
        assert entry["event_type"] == "mcp_call"
        assert "timestamp" in entry

    def test_log_entry_has_iso_timestamp(self):
        from lib.logging_schema import create_log_entry
        entry = create_log_entry("s", "sk", "mcp_call", "info", {})
        datetime.fromisoformat(entry["timestamp"])

    def test_valid_event_types(self):
        from lib.logging_schema import VALID_EVENT_TYPES
        assert "mcp_call" in VALID_EVENT_TYPES
        assert "enrichment" in VALID_EVENT_TYPES
        assert "error" in VALID_EVENT_TYPES
        assert "metric" in VALID_EVENT_TYPES

    def test_valid_severities(self):
        from lib.logging_schema import VALID_SEVERITIES
        assert set(VALID_SEVERITIES) == {"info", "warn", "error", "critical"}

    def test_invalid_event_type_raises(self):
        from lib.logging_schema import create_log_entry
        with pytest.raises(ValueError, match="Invalid event_type"):
            create_log_entry("s", "sk", "invalid_type", "info", {})

    def test_invalid_severity_raises(self):
        from lib.logging_schema import create_log_entry
        with pytest.raises(ValueError, match="Invalid severity"):
            create_log_entry("s", "sk", "mcp_call", "debug", {})

    def test_log_entry_serializable(self):
        from lib.logging_schema import create_log_entry
        entry = create_log_entry("s", "sk", "mcp_call", "info", {"key": "value"})
        serialized = json.dumps(entry)
        assert isinstance(serialized, str)


class TestErrorClassification:

    def test_classify_transient_error(self):
        from lib.logging_schema import classify_error
        result = classify_error(429, "Rate limit exceeded")
        assert result["class"] == "TRANSIENT"
        assert result["recovery"] == "exponential_backoff"

    def test_classify_auth_error(self):
        from lib.logging_schema import classify_error
        result = classify_error(401, "Unauthorized")
        assert result["class"] == "AUTH"
        assert result["recovery"] == "skip_server"

    def test_classify_not_found(self):
        from lib.logging_schema import classify_error
        result = classify_error(404, "Not found")
        assert result["class"] == "NOT_FOUND"

    def test_classify_server_error(self):
        from lib.logging_schema import classify_error
        result = classify_error(500, "Internal server error")
        assert result["class"] == "TRANSIENT"

    def test_classify_unknown_error(self):
        from lib.logging_schema import classify_error
        result = classify_error(0, "Connection refused")
        assert result["class"] == "UNAVAILABLE"

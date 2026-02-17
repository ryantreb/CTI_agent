#!/usr/bin/env python3
"""Tests for MCP server health check utility."""

from unittest.mock import patch


class TestHealthReport:
    def test_create_health_report_structure(self):
        from lib.health_check import create_health_report

        report = create_health_report(
            available=["gti", "mcp-threatintel"],
            unavailable=["mcp-shodan"],
            missing_keys=["SHODAN_API_KEY"],
            degraded_capabilities=["IP enrichment via Shodan unavailable"],
        )
        assert report["total_servers"] == 3
        assert report["available_count"] == 2
        assert report["unavailable_count"] == 1
        assert "SHODAN_API_KEY" in report["missing_keys"]

    def test_check_env_keys(self):
        from lib.health_check import check_env_keys

        with patch.dict("os.environ", {"VT_API_KEY": "test123"}, clear=False):
            present, missing = check_env_keys(["VT_API_KEY", "NONEXISTENT_KEY"])
            assert "VT_API_KEY" in present
            assert "NONEXISTENT_KEY" in missing

    def test_degraded_capability_message_for_missing_shodan(self):
        from lib.health_check import get_degraded_capabilities

        result = get_degraded_capabilities(unavailable_servers=["mcp-shodan"])
        assert any("Shodan" in cap or "shodan" in cap for cap in result)

    def test_no_degradation_when_all_available(self):
        from lib.health_check import get_degraded_capabilities

        result = get_degraded_capabilities(unavailable_servers=[])
        assert result == []

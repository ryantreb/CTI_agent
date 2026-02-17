#!/usr/bin/env python3
"""Tests for MCP server configuration loading and validation."""

import json
import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


class TestMcpServerRegistry:
    """Validate mcp_server_registry.json schema and contents."""

    @pytest.fixture
    def registry(self):
        path = PROJECT_ROOT / "config" / "mcp_server_registry.json"
        with open(path) as f:
            return json.load(f)

    def test_registry_has_servers(self, registry):
        assert "servers" in registry
        assert len(registry["servers"]) >= 23

    def test_each_server_has_required_fields(self, registry):
        required = {"name", "repo", "command", "category", "tier", "requires_api_key"}
        for server in registry["servers"]:
            missing = required - set(server.keys())
            assert not missing, f"Server {server.get('name', '???')} missing: {missing}"

    def test_tier_values_valid(self, registry):
        valid_tiers = {1, 2, 3, 4}
        for server in registry["servers"]:
            assert server["tier"] in valid_tiers, (
                f"{server['name']} has invalid tier {server['tier']}"
            )

    def test_category_values_valid(self, registry):
        valid = {
            "intelligence",
            "enrichment",
            "vulnerability",
            "malware-analysis",
            "osint",
            "utility",
        }
        for server in registry["servers"]:
            assert server["category"] in valid, f"{server['name']} has invalid category"

    def test_no_duplicate_names(self, registry):
        names = [s["name"] for s in registry["servers"]]
        assert len(names) == len(set(names)), (
            f"Duplicate server names: {[n for n in names if names.count(n) > 1]}"
        )

    def test_api_key_env_var_present_when_required(self, registry):
        for server in registry["servers"]:
            if server["requires_api_key"]:
                assert "api_key_env_var" in server, (
                    f"{server['name']} requires key but no env var specified"
                )

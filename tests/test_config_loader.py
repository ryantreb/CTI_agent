#!/usr/bin/env python3
"""Tests for config loading and validation."""

import json
import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


class TestConfigLoader:
    """Test config loading from registry."""

    def test_load_registry(self):
        from lib.config import load_server_registry
        registry = load_server_registry()
        assert len(registry["servers"]) >= 23

    def test_get_servers_by_tier(self):
        from lib.config import get_servers_by_tier
        tier1 = get_servers_by_tier(1)
        assert len(tier1) >= 10

    def test_get_servers_by_category(self):
        from lib.config import get_servers_by_category
        vuln = get_servers_by_category("vulnerability")
        assert len(vuln) >= 5

    def test_get_routing_for_ioc_type(self):
        from lib.config import get_routing
        ip_routing = get_routing("ip")
        assert "primary" in ip_routing
        assert "gti" in ip_routing["primary"]

    def test_get_routing_unknown_type_returns_empty(self):
        from lib.config import get_routing
        result = get_routing("nonexistent")
        assert result == {"primary": [], "secondary": [], "fallback": []}

    def test_get_servers_requiring_api_keys(self):
        from lib.config import get_servers_requiring_keys
        keyed = get_servers_requiring_keys()
        names = [s["name"] for s in keyed]
        assert "gti" in names
        assert "mcp-nvd" not in names

    def test_generate_mcp_config_json(self):
        from lib.config import generate_mcp_config
        config = generate_mcp_config()
        assert "mcpServers" in config
        assert "feedly" in config["mcpServers"]
        assert "command" in config["mcpServers"]["feedly"]

#!/usr/bin/env python3
"""
CTI Agent Configuration Loader

Loads MCP server registry, provides routing tables,
and generates Claude Code mcp_config.json from the registry.
"""

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = PROJECT_ROOT / "config" / "mcp_server_registry.json"


def load_server_registry() -> dict[str, Any]:
    """Load the MCP server registry."""
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def get_servers_by_tier(tier: int) -> list[dict]:
    """Return all servers in the given tier."""
    registry = load_server_registry()
    return [s for s in registry["servers"] if s["tier"] == tier]


def get_servers_by_category(category: str) -> list[dict]:
    """Return all servers in the given category."""
    registry = load_server_registry()
    return [s for s in registry["servers"] if s["category"] == category]


def get_routing(ioc_type: str) -> dict[str, list[str]]:
    """Return the routing chain for an IOC type."""
    registry = load_server_registry()
    routing = registry.get("routing", {})
    return routing.get(ioc_type, {"primary": [], "secondary": [], "fallback": []})


def get_servers_requiring_keys() -> list[dict]:
    """Return servers that require API keys."""
    registry = load_server_registry()
    return [s for s in registry["servers"] if s["requires_api_key"]]


def generate_mcp_config() -> dict[str, Any]:
    """Generate Claude Code mcp_config.json from the registry."""
    registry = load_server_registry()
    mcp_servers = {}
    for server in registry["servers"]:
        entry = {
            "command": server["command"],
            "args": server["args"],
        }
        if server.get("env"):
            entry["env"] = server["env"]
        mcp_servers[server["name"]] = entry
    return {"mcpServers": mcp_servers}

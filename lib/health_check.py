#!/usr/bin/env python3
"""
JTIA Server Health Check Utility

Checks API key availability, server connectivity,
and reports degraded capabilities.
"""

import os
from lib.config import load_server_registry, get_servers_requiring_keys


# Maps server names to capability descriptions lost when unavailable
CAPABILITY_MAP = {
    "mcp-shodan": "IP enrichment via Shodan (device/service/vulnerability data)",
    "mcp-censys": "Certificate transparency and attack surface mapping via Censys",
    "otx-mcp": "AlienVault OTX community threat intelligence",
    "mallory-mcp-server": "Real-time threat actor and malware data via Mallory",
    "gti": "VirusTotal file/domain/IP analysis (core enrichment)",
    "feedly": "Feedly threat intelligence feeds (core collection)",
    "fastmcp-threatintel": "Multi-source IOC aggregation (AbuseIPDB, VirusTotal)",
    "ghidra-mcp": "Binary decompilation and reverse engineering",
    "yara-mcp": "YARA malware signature matching",
    "capa-mcp": "Executable capability detection (ATT&CK mapping)",
    "radare2-mcp": "Binary disassembly and decompilation",
    "binwalk-mcp": "Firmware analysis and file extraction",
    "nuclei-mcp": "Active vulnerability scanning",
}


def check_env_keys(key_names: list[str]) -> tuple[list[str], list[str]]:
    """Check which environment variables are set.

    Returns (present, missing) lists of key names.
    """
    present = [k for k in key_names if os.environ.get(k)]
    missing = [k for k in key_names if not os.environ.get(k)]
    return present, missing


def get_degraded_capabilities(unavailable_servers: list[str]) -> list[str]:
    """Return human-readable list of capabilities lost due to unavailable servers."""
    return [
        CAPABILITY_MAP[server]
        for server in unavailable_servers
        if server in CAPABILITY_MAP
    ]


def create_health_report(
    available: list[str],
    unavailable: list[str],
    missing_keys: list[str],
    degraded_capabilities: list[str],
) -> dict:
    """Create a structured health report."""
    total = len(available) + len(unavailable)
    return {
        "total_servers": total,
        "available_count": len(available),
        "unavailable_count": len(unavailable),
        "available_servers": available,
        "unavailable_servers": unavailable,
        "missing_keys": missing_keys,
        "degraded_capabilities": degraded_capabilities,
        "health_percentage": round(len(available) / total * 100, 1) if total > 0 else 0,
    }


def run_health_check() -> dict:
    """Run a full health check against the server registry.

    Checks API key availability for all servers that require keys.
    Returns a health report dict.
    """
    registry = load_server_registry()
    keyed_servers = get_servers_requiring_keys()

    # Check which API keys are present
    all_key_vars = list({s["api_key_env_var"] for s in keyed_servers if "api_key_env_var" in s})
    present_keys, missing_keys = check_env_keys(all_key_vars)

    # Determine availability based on key presence
    available = []
    unavailable = []

    for server in registry["servers"]:
        if not server["requires_api_key"]:
            available.append(server["name"])
        elif server.get("api_key_env_var") and os.environ.get(server["api_key_env_var"]):
            available.append(server["name"])
        else:
            unavailable.append(server["name"])

    degraded = get_degraded_capabilities(unavailable)

    return create_health_report(available, unavailable, missing_keys, degraded)

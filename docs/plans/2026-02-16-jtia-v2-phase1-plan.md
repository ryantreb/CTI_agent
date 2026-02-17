# CTI Agent v2.0 Phase 1 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand CTI Agent from 3 to 23 MCP servers with dynamic routing, graceful degradation, structured logging, and two new skills (check-server-health, plan-session).

**Architecture:** Incremental layering on existing SKILL.md prompt-orchestration. New MCP servers added to `config/mcp_config.json`. Routing logic added to `enrich-iocs` SKILL.md. New skills follow existing SKILL.md conventions. Python utilities in `lib/` for shared logic (health checks, logging schema, config validation).

**Tech Stack:** Python 3.10+ (stdlib + httpx + pydantic), JSON configs, Markdown skills, GitHub Actions CI, pytest for tests.

**Design Doc:** `docs/plans/2026-02-16-jtia-v2-design.md`

---

## Task 1: Project Scaffolding

**Files:**
- Create: `lib/__init__.py`
- Create: `lib/config.py`
- Create: `tests/__init__.py`
- Create: `tests/test_config.py`
- Create: `config/mcp_server_registry.json`
- Modify: `requirements.txt`

**Why this first:** Every subsequent task depends on a validated config structure. The server registry is the single source of truth for all 23 MCP servers.

**Step 1: Write the failing test**

Create `tests/__init__.py` (empty) and `tests/test_config.py`:

```python
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
            assert server["tier"] in valid_tiers, f"{server['name']} has invalid tier {server['tier']}"

    def test_category_values_valid(self, registry):
        valid = {"intelligence", "enrichment", "vulnerability", "malware-analysis", "osint", "utility"}
        for server in registry["servers"]:
            assert server["category"] in valid, f"{server['name']} has invalid category"

    def test_no_duplicate_names(self, registry):
        names = [s["name"] for s in registry["servers"]]
        assert len(names) == len(set(names)), f"Duplicate server names: {[n for n in names if names.count(n) > 1]}"

    def test_api_key_env_var_present_when_required(self, registry):
        for server in registry["servers"]:
            if server["requires_api_key"]:
                assert "api_key_env_var" in server, f"{server['name']} requires key but no env var specified"
```

**Step 2: Create lib/ package**

Create `lib/__init__.py`:
```python
"""CTI Agent shared library utilities."""
```

**Step 3: Run tests to verify they fail**

Run: `cd "/home/ryantreb/Security Projects/CTI_agent" && python -m pytest tests/test_config.py -v`
Expected: FAIL (mcp_server_registry.json doesn't exist yet)

**Step 4: Create the server registry**

Create `config/mcp_server_registry.json`:

```json
{
  "schema_version": "2.0",
  "description": "CTI Agent MCP Server Registry - single source of truth for all server configurations",
  "servers": [
    {
      "name": "feedly",
      "repo": "https://github.com/feedly/feedly-mcp",
      "command": "uvx",
      "args": ["feedly-mcp"],
      "env": {"FEEDLY_ACCESS_TOKEN": "${FEEDLY_ACCESS_TOKEN}"},
      "category": "intelligence",
      "tier": 1,
      "requires_api_key": true,
      "api_key_env_var": "FEEDLY_ACCESS_TOKEN",
      "description": "Feedly Threat Intelligence - feeds, trending threats, actor profiles",
      "rate_limit": {"requests_per_day": null, "notes": "Enterprise plan"}
    },
    {
      "name": "gti",
      "repo": "https://github.com/google/mcp-security",
      "command": "uvx",
      "args": ["gti_mcp"],
      "env": {"VT_API_KEY": "${VT_API_KEY}"},
      "category": "enrichment",
      "tier": 1,
      "requires_api_key": true,
      "api_key_env_var": "VT_API_KEY",
      "description": "Google Threat Intelligence (VirusTotal) - file/domain/IP analysis",
      "rate_limit": {"requests_per_day": 1000, "notes": "Free tier"}
    },
    {
      "name": "fastmcp-threatintel",
      "repo": "https://github.com/4R9UN/fastmcp-threatintel",
      "command": "threatintel",
      "args": ["server", "--port", "8001"],
      "env": {"VT_API_KEY": "${VT_API_KEY}", "ABUSEIPDB_API_KEY": "${ABUSEIPDB_API_KEY}"},
      "category": "enrichment",
      "tier": 1,
      "requires_api_key": true,
      "api_key_env_var": "VT_API_KEY",
      "description": "Multi-source IOC aggregation",
      "rate_limit": {"requests_per_day": 1000, "notes": "Inherits VT rate limit"}
    },
    {
      "name": "mcp-shodan",
      "repo": "https://github.com/BurtTheCoder/mcp-shodan",
      "command": "npx",
      "args": ["-y", "mcp-shodan"],
      "env": {"SHODAN_API_KEY": "${SHODAN_API_KEY}"},
      "category": "enrichment",
      "tier": 1,
      "requires_api_key": true,
      "api_key_env_var": "SHODAN_API_KEY",
      "description": "Shodan - internet device/vulnerability data for IPs",
      "rate_limit": {"requests_per_month": 100, "notes": "Free tier"}
    },
    {
      "name": "otx-mcp",
      "repo": "https://github.com/mrwadams/otx-mcp",
      "command": "uvx",
      "args": ["otx-mcp"],
      "env": {"OTX_API_KEY": "${OTX_API_KEY}"},
      "category": "intelligence",
      "tier": 1,
      "requires_api_key": true,
      "api_key_env_var": "OTX_API_KEY",
      "description": "AlienVault OTX community threat intelligence",
      "rate_limit": {"requests_per_day": null, "notes": "Free, generous limits"}
    },
    {
      "name": "mcp-threatintel",
      "repo": "https://github.com/aplaceforallmystuff/mcp-threatintel",
      "command": "uvx",
      "args": ["mcp-threatintel"],
      "env": {},
      "category": "enrichment",
      "tier": 1,
      "requires_api_key": false,
      "description": "GreyNoise, abuse.ch (Feodo/URLhaus/MalwareBazaar/ThreatFox)",
      "rate_limit": {"requests_per_day": null, "notes": "Public APIs"}
    },
    {
      "name": "ti-mindmap-hub-mcp",
      "repo": "https://github.com/TI-Mindmap-HUB-Org/ti-mindmap-hub-mcp",
      "command": "uvx",
      "args": ["ti-mindmap-hub-mcp"],
      "env": {},
      "category": "intelligence",
      "tier": 1,
      "requires_api_key": false,
      "description": "Automated report analysis, STIX 2.1 gen, IOC extraction, CVE intel",
      "rate_limit": {"requests_per_day": null, "notes": "Local processing"}
    },
    {
      "name": "mcp-security-orkl",
      "repo": "https://github.com/fr0gger/MCP_Security",
      "command": "uvx",
      "args": ["mcp-security"],
      "env": {},
      "category": "intelligence",
      "tier": 1,
      "requires_api_key": false,
      "description": "ORKL threat reports and actor analysis",
      "rate_limit": {"requests_per_day": null, "notes": "Public API"}
    },
    {
      "name": "mcp-censys",
      "repo": "https://github.com/nickpending/mcp-censys",
      "command": "uvx",
      "args": ["mcp-censys"],
      "env": {"CENSYS_API_ID": "${CENSYS_API_ID}", "CENSYS_API_SECRET": "${CENSYS_API_SECRET}"},
      "category": "enrichment",
      "tier": 1,
      "requires_api_key": true,
      "api_key_env_var": "CENSYS_API_ID",
      "description": "Certificate transparency, attack surface mapping",
      "rate_limit": {"requests_per_month": 250, "notes": "Free tier"}
    },
    {
      "name": "mallory-mcp-server",
      "repo": "https://github.com/malloryai/mallory-mcp-server",
      "command": "uvx",
      "args": ["mallory-mcp-server"],
      "env": {"MALLORY_API_KEY": "${MALLORY_API_KEY}"},
      "category": "intelligence",
      "tier": 1,
      "requires_api_key": true,
      "api_key_env_var": "MALLORY_API_KEY",
      "description": "Real-time threat actor, malware, TTPs data",
      "rate_limit": {"requests_per_day": null, "notes": "Check provider"}
    },
    {
      "name": "mcp-nvd",
      "repo": "https://github.com/marcoeg/mcp-nvd",
      "command": "uvx",
      "args": ["mcp-nvd"],
      "env": {},
      "category": "vulnerability",
      "tier": 2,
      "requires_api_key": false,
      "description": "NIST NVD CVE lookups, CVSS scores",
      "rate_limit": {"requests_per_30s": 50, "notes": "NVD public API rolling window"}
    },
    {
      "name": "epss-mcp",
      "repo": "https://github.com/jgamblin/EPSS-MCP",
      "command": "uvx",
      "args": ["epss-mcp"],
      "env": {},
      "category": "vulnerability",
      "tier": 2,
      "requires_api_key": false,
      "description": "Exploit Prediction Scoring System",
      "rate_limit": {"requests_per_day": null, "notes": "Public API"}
    },
    {
      "name": "kev-mcp",
      "repo": "https://github.com/yeger00/kev-mcp",
      "command": "uvx",
      "args": ["kev-mcp"],
      "env": {},
      "category": "vulnerability",
      "tier": 2,
      "requires_api_key": false,
      "description": "CISA Known Exploited Vulnerabilities catalog",
      "rate_limit": {"requests_per_day": null, "notes": "Public catalog"}
    },
    {
      "name": "vulnerability-intelligence-mcp",
      "repo": "https://github.com/firetix/vulnerability-intelligence-mcp-server",
      "command": "uvx",
      "args": ["vulnerability-intelligence-mcp"],
      "env": {},
      "category": "vulnerability",
      "tier": 2,
      "requires_api_key": false,
      "description": "CVE + EPSS + CVSS + exploit detection unified",
      "rate_limit": {"requests_per_day": null, "notes": "Aggregates public APIs"}
    },
    {
      "name": "nuclei-mcp",
      "repo": "https://github.com/addcontent/nuclei-mcp",
      "command": "uvx",
      "args": ["nuclei-mcp"],
      "env": {},
      "category": "vulnerability",
      "tier": 2,
      "requires_api_key": false,
      "description": "Active vulnerability scanning with 8000+ Nuclei templates",
      "rate_limit": {"requests_per_day": null, "notes": "Local scanning"}
    },
    {
      "name": "ghidra-mcp",
      "repo": "https://github.com/LaurieWired/GhidraMCP",
      "command": "python",
      "args": ["-m", "ghidra_mcp"],
      "env": {},
      "category": "malware-analysis",
      "tier": 3,
      "requires_api_key": false,
      "description": "Deep binary decompilation and reverse engineering",
      "rate_limit": {"requests_per_day": null, "notes": "Local tool"}
    },
    {
      "name": "yara-mcp",
      "repo": "https://github.com/FuzzingLabs/mcp-security-hub",
      "command": "docker",
      "args": ["compose", "up", "yara-mcp", "-d"],
      "env": {},
      "category": "malware-analysis",
      "tier": 3,
      "requires_api_key": false,
      "description": "YARA malware signature matching and classification",
      "rate_limit": {"requests_per_day": null, "notes": "Local tool"}
    },
    {
      "name": "capa-mcp",
      "repo": "https://github.com/FuzzingLabs/mcp-security-hub",
      "command": "docker",
      "args": ["compose", "up", "capa-mcp", "-d"],
      "env": {},
      "category": "malware-analysis",
      "tier": 3,
      "requires_api_key": false,
      "description": "Executable capability detection (maps to ATT&CK)",
      "rate_limit": {"requests_per_day": null, "notes": "Local tool"}
    },
    {
      "name": "radare2-mcp",
      "repo": "https://github.com/FuzzingLabs/mcp-security-hub",
      "command": "docker",
      "args": ["compose", "up", "radare2-mcp", "-d"],
      "env": {},
      "category": "malware-analysis",
      "tier": 3,
      "requires_api_key": false,
      "description": "Disassembly, decompilation, binary analysis",
      "rate_limit": {"requests_per_day": null, "notes": "Local tool"}
    },
    {
      "name": "binwalk-mcp",
      "repo": "https://github.com/FuzzingLabs/mcp-security-hub",
      "command": "docker",
      "args": ["compose", "up", "binwalk-mcp", "-d"],
      "env": {},
      "category": "malware-analysis",
      "tier": 3,
      "requires_api_key": false,
      "description": "Firmware analysis, file extraction, signature scanning",
      "rate_limit": {"requests_per_day": null, "notes": "Local tool"}
    },
    {
      "name": "mcp-dnstwist",
      "repo": "https://github.com/BurtTheCoder/mcp-dnstwist",
      "command": "npx",
      "args": ["-y", "mcp-dnstwist"],
      "env": {},
      "category": "osint",
      "tier": 4,
      "requires_api_key": false,
      "description": "Phishing and typosquatting domain detection",
      "rate_limit": {"requests_per_day": null, "notes": "Local DNS queries"}
    },
    {
      "name": "networksdb-mcp",
      "repo": "https://github.com/MorDavid/NetworksDB-MCP",
      "command": "uvx",
      "args": ["networksdb-mcp"],
      "env": {},
      "category": "osint",
      "tier": 4,
      "requires_api_key": false,
      "description": "IP, ASN, and DNS record lookups",
      "rate_limit": {"requests_per_day": null, "notes": "Public API"}
    },
    {
      "name": "cyberchef-api-mcp",
      "repo": "https://github.com/slouchd/cyberchef-api-mcp-server",
      "command": "uvx",
      "args": ["cyberchef-api-mcp"],
      "env": {},
      "category": "utility",
      "tier": 4,
      "requires_api_key": false,
      "description": "Data transformation, encoding/decoding, hash operations",
      "rate_limit": {"requests_per_day": null, "notes": "Local processing"}
    }
  ],
  "routing": {
    "ip": {
      "primary": ["gti", "mcp-shodan"],
      "secondary": ["fastmcp-threatintel", "mcp-threatintel"],
      "fallback": ["networksdb-mcp"]
    },
    "domain": {
      "primary": ["gti"],
      "secondary": ["mcp-censys", "mcp-dnstwist"],
      "fallback": ["networksdb-mcp"]
    },
    "hash": {
      "primary": ["gti"],
      "secondary": ["mcp-threatintel"],
      "fallback": []
    },
    "url": {
      "primary": ["gti"],
      "secondary": ["mcp-threatintel"],
      "fallback": []
    },
    "cve": {
      "primary": ["mcp-nvd"],
      "secondary": ["epss-mcp", "kev-mcp"],
      "fallback": ["vulnerability-intelligence-mcp"]
    },
    "threat_actor": {
      "primary": ["gti", "feedly"],
      "secondary": ["otx-mcp", "mcp-security-orkl"],
      "fallback": ["mallory-mcp-server"]
    }
  }
}
```

**Step 5: Update requirements.txt**

Add to `requirements.txt`:
```
# ===========================================
# Testing
# ===========================================
pytest>=8.0.0
```

**Step 6: Run tests to verify they pass**

Run: `cd "/home/ryantreb/Security Projects/CTI_agent" && pip install pytest && python -m pytest tests/test_config.py -v`
Expected: All 6 tests PASS

**Step 7: Commit**

```bash
git add lib/ tests/ config/mcp_server_registry.json requirements.txt
git commit -m "feat: add MCP server registry with 23 servers and test suite"
```

---

## Task 2: Updated .env.template

**Files:**
- Modify: `config/.env.template`
- Modify: `.env.example`

**Step 1: Update .env.template with all API keys**

Replace `config/.env.template` contents:

```bash
# ============================================
# CTI Agent v2.0 API Key Configuration
# ============================================
# Copy this file to config/.env and fill in your keys.
# Keys marked REQUIRED are needed for core functionality.
# Keys marked OPTIONAL enable additional enrichment sources.
# Keys marked NONE are for servers that use public/local APIs.

# === REQUIRED (Core functionality) ===
FEEDLY_ACCESS_TOKEN=       # Feedly Threat Intelligence
VT_API_KEY=                # VirusTotal / Google Threat Intelligence

# === TIER 1 OPTIONAL (Enhanced enrichment) ===
SHODAN_API_KEY=            # Shodan (free tier: 100 queries/month)
OTX_API_KEY=               # AlienVault OTX (free)
CENSYS_API_ID=             # Censys (free tier: 250 queries/month)
CENSYS_API_SECRET=         # Censys API secret
ABUSEIPDB_API_KEY=         # AbuseIPDB (free tier: 1000 queries/day)
MALLORY_API_KEY=           # Mallory threat intel

# === TIER 2-4: No API keys required ===
# mcp-nvd, epss-mcp, kev-mcp, vulnerability-intelligence-mcp,
# nuclei-mcp, mcp-threatintel, ti-mindmap-hub-mcp, mcp-security-orkl,
# ghidra-mcp, yara-mcp, capa-mcp, radare2-mcp, binwalk-mcp,
# mcp-dnstwist, networksdb-mcp, cyberchef-api-mcp
# All use public APIs or run locally.

# === PROXY (Optional) ===
# HTTP_PROXY=
# HTTPS_PROXY=
```

**Step 2: Update .env.example** to match the same content.

**Step 3: Commit**

```bash
git add config/.env.template .env.example
git commit -m "feat: update env templates with all 23 MCP server API keys"
```

---

## Task 3: Config Validation Utility

**Files:**
- Create: `lib/config.py`
- Create: `tests/test_config_loader.py`

**Step 1: Write the failing test**

Create `tests/test_config_loader.py`:

```python
#!/usr/bin/env python3
"""Tests for config loading and validation."""

import json
import pytest
from pathlib import Path

# We'll import after creating the module
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
        assert len(tier1) >= 10  # 3 original + 7 new

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
        assert "mcp-nvd" not in names  # NVD is free

    def test_generate_mcp_config_json(self):
        from lib.config import generate_mcp_config
        config = generate_mcp_config()
        assert "mcpServers" in config
        assert "feedly" in config["mcpServers"]
        assert "command" in config["mcpServers"]["feedly"]
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_config_loader.py -v`
Expected: FAIL (lib.config doesn't exist)

**Step 3: Write the implementation**

Create `lib/config.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_config_loader.py -v`
Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add lib/config.py tests/test_config_loader.py
git commit -m "feat: add config loader with routing, tier, and category queries"
```

---

## Task 4: Structured Logging Foundation

**Files:**
- Create: `lib/logging_schema.py`
- Create: `tests/test_logging.py`

**Step 1: Write the failing test**

Create `tests/test_logging.py`:

```python
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
        # Should parse as ISO 8601
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
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_logging.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `lib/logging_schema.py`:

```python
#!/usr/bin/env python3
"""
CTI Agent Structured Logging Schema

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
    """Create a structured log entry conforming to CTI Agent schema."""
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
    """
    Classify an error by HTTP status code and message.

    Returns dict with 'class', 'recovery', and 'description'.
    """
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
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_logging.py -v`
Expected: All 12 tests PASS

**Step 5: Commit**

```bash
git add lib/logging_schema.py tests/test_logging.py
git commit -m "feat: add structured logging schema with error classification"
```

---

## Task 5: Server Health Check Utility

**Files:**
- Create: `lib/health_check.py`
- Create: `tests/test_health_check.py`

**Step 1: Write the failing test**

Create `tests/test_health_check.py`:

```python
#!/usr/bin/env python3
"""Tests for MCP server health check utility."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestHealthReport:

    def test_create_health_report_structure(self):
        from lib.health_check import create_health_report
        report = create_health_report(
            available=["gti", "mcp-nvd"],
            unavailable=["mcp-shodan"],
            missing_keys=["SHODAN_API_KEY"],
            degraded_capabilities=["IP enrichment via Shodan unavailable"]
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
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_health_check.py -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `lib/health_check.py`:

```python
#!/usr/bin/env python3
"""
CTI Agent Server Health Check Utility

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
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_health_check.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add lib/health_check.py tests/test_health_check.py
git commit -m "feat: add server health check utility with degraded capability reporting"
```

---

## Task 6: check-server-health Skill

**Files:**
- Create: `skills/check-server-health/SKILL.md`
- Modify: `AGENT.md` (add to skill registry)
- Modify: `state/skill_versions.json` (add entry)

**Step 1: Create the skill**

Create `skills/check-server-health/SKILL.md`:

```markdown
---
name: check-server-health
description: Run at session start to verify MCP server availability, check API keys, and report degraded capabilities. Adjusts the session execution plan based on available resources.
---

# Check Server Health Skill

## Purpose
Verify which MCP servers are available before beginning intelligence operations. Report degraded capabilities so downstream skills can adjust their routing.

## Position in Workflow

```
SESSION START → **check-server-health** → plan-session → monitor-feeds → ...
```

This skill runs FIRST in every session, before plan-session.

## Protocol

### Step 1: Load Server Registry
```
LOAD config/mcp_server_registry.json
EXTRACT all server entries with their tier, category, and API key requirements
```

### Step 2: Check API Key Availability
```
FOR EACH server WHERE requires_api_key == true:
  CHECK if api_key_env_var is set in environment
  IF missing:
    LOG warning: "{server_name} unavailable - missing {api_key_env_var}"
    ADD to unavailable_servers list
  ELSE:
    ADD to available_servers list

FOR EACH server WHERE requires_api_key == false:
  ADD to available_servers list (assumed available)
```

### Step 3: Generate Health Report
```
REPORT:
  - Total servers: {count}
  - Available: {count} ({percentage}%)
  - Unavailable: {count}
  - Missing API keys: [list]
  - Degraded capabilities: [human-readable list]
```

### Step 4: Adjust Routing Table
```
FOR EACH ioc_type IN routing table:
  REMOVE unavailable servers from primary/secondary/fallback chains
  IF primary chain is empty:
    PROMOTE secondary to primary
  IF all chains empty:
    LOG error: "No servers available for {ioc_type} enrichment"
    ADD to degraded_capabilities
```

### Step 5: Update Session State
```
WRITE health report to memory/scratchpad.md
UPDATE state/active_context.md with server availability
```

## Output Schema

```json
{
  "skill": "check-server-health",
  "timestamp": "ISO8601",
  "health": {
    "total_servers": 23,
    "available_count": 19,
    "unavailable_count": 4,
    "health_percentage": 82.6,
    "available_servers": ["gti", "feedly", "mcp-nvd", ...],
    "unavailable_servers": ["mcp-shodan", "mcp-censys", ...],
    "missing_keys": ["SHODAN_API_KEY", "CENSYS_API_ID"],
    "degraded_capabilities": [
      "IP enrichment via Shodan unavailable",
      "Certificate transparency via Censys unavailable"
    ]
  },
  "adjusted_routing": {
    "ip": {"primary": ["gti"], "secondary": ["fastmcp-threatintel"], "fallback": ["networksdb-mcp"]},
    "domain": {"primary": ["gti"], "secondary": ["mcp-dnstwist"], "fallback": ["networksdb-mcp"]}
  }
}
```

## Severity Thresholds

| Health % | Severity | Action |
|----------|----------|--------|
| 90-100% | Green | Proceed normally |
| 70-89% | Yellow | Proceed with noted degradation |
| 50-69% | Orange | Warn user, limited enrichment |
| <50% | Red | Alert user, recommend fixing keys before proceeding |

## Integration

- **Runs before**: plan-session (always)
- **Output consumed by**: plan-session, enrich-iocs, verify-claims
- **State written to**: memory/scratchpad.md, state/active_context.md
```

**Step 2: Add to AGENT.md skill registry**

In `AGENT.md`, add `check-server-health` to the Skill Registry table with priority 0 (runs before plan-session) and no dependencies.

**Step 3: Add to skill_versions.json**

Add `check-server-health` entry with version 0, status "baseline".

**Step 4: Commit**

```bash
git add skills/check-server-health/SKILL.md AGENT.md state/skill_versions.json
git commit -m "feat: add check-server-health skill for session-start diagnostics"
```

---

## Task 7: plan-session Skill

**Files:**
- Create: `skills/plan-session/SKILL.md`
- Modify: `AGENT.md` (already referenced but skill didn't exist)
- Modify: `state/skill_versions.json`

**Step 1: Create the skill**

Create `skills/plan-session/SKILL.md`:

```markdown
---
name: plan-session
description: Generate a prioritized execution plan at session start. Considers user goals, server availability (from check-server-health), stale items, and pending work. Must run before any collection or analysis skills.
---

# Plan Session Skill

## Purpose
Generate a prioritized execution plan based on user goals, available resources, and pending work from previous sessions.

## Position in Workflow

```
check-server-health → **plan-session** → [execute planned skills in order]
```

## Protocol

### Step 1: Gather Context
```
1. READ state/active_context.md for pending work from last session
2. READ memory/scratchpad.md for in-progress analysis
3. READ health report from check-server-health output
4. READ alerts/pending.json for unprocessed alerts
5. READ state/processed_guids.json for dedup context
6. PARSE user's stated goal/priority for this session
```

### Step 2: Determine Session Type
```
IF user specifies a target (APT, CVE, campaign):
  session_type = "focused"
  primary_goal = user_specified_target

ELIF pending alerts exist:
  session_type = "alert_response"
  primary_goal = highest_priority_alert

ELIF stale items need re-enrichment:
  session_type = "maintenance"
  primary_goal = "Re-enrich stale IOCs and update profiles"

ELSE:
  session_type = "discovery"
  primary_goal = "Scan feeds for new threats"
```

### Step 3: Build Execution Plan
```
ALWAYS include:
  1. check-server-health (already completed)

IF session_type == "focused":
  2. monitor-feeds (filtered to target topic)
  3. enrich-iocs (all IOCs from target)
  4. verify-claims
  5. diamond-model-analysis
  6. analysis-competing-hypotheses (if attribution needed)
  7. generate-report

IF session_type == "discovery":
  2. monitor-feeds (broad scan)
  3. enrich-iocs (top N by priority)
  4. verify-claims
  5. diamond-model-analysis (if sufficient data)
  6. generate-report (if analysis completed)

IF session_type == "alert_response":
  2. enrich-iocs (alert IOCs only, expedited)
  3. verify-claims
  4. diamond-model-analysis
  5. generate-report (tactical format)

IF session_type == "maintenance":
  2. [re-enrichment of stale items]
  3. [actor profile updates]
```

### Step 4: Adjust for Degraded Servers
```
FOR EACH planned skill:
  CHECK if required MCP servers are available
  IF not:
    ADD caveat to plan: "Limited enrichment - {server} unavailable"
    ADJUST expected outputs accordingly
```

### Step 5: Present Plan to User
```
OUTPUT:
  Session Type: {type}
  Primary Goal: {goal}
  Available Servers: {count}/{total} ({percentage}%)

  Execution Plan:
  1. [Skill] - [Purpose] - [Expected output]
  2. [Skill] - [Purpose] - [Expected output]
  ...

  Caveats:
  - [Any degraded capabilities]

  Estimated IOCs to process: {count}

  Proceed? (User confirms or adjusts)
```

## Output Schema

```json
{
  "skill": "plan-session",
  "timestamp": "ISO8601",
  "session_type": "focused|discovery|alert_response|maintenance",
  "primary_goal": "description",
  "execution_plan": [
    {
      "order": 1,
      "skill": "monitor-feeds",
      "purpose": "Collect intelligence on APT29 activity",
      "mcp_servers_required": ["feedly", "gti"],
      "expected_output": "Enrichment queue with relevant IOCs"
    }
  ],
  "caveats": ["Shodan unavailable - IP enrichment limited to GTI"],
  "estimated_items": 15,
  "user_confirmed": false
}
```

## Integration

- **Requires input from**: check-server-health
- **Output consumed by**: All downstream skills (determines execution order)
- **State written to**: state/active_context.md, memory/scratchpad.md
```

**Step 2: Update AGENT.md and skill_versions.json**

Same pattern as Task 6.

**Step 3: Commit**

```bash
git add skills/plan-session/SKILL.md AGENT.md state/skill_versions.json
git commit -m "feat: add plan-session skill for session-start execution planning"
```

---

## Task 8: Update enrich-iocs Skill with Dynamic Routing

**Files:**
- Modify: `skills/enrich-iocs/SKILL.md`

**Step 1: Read current skill** (already read earlier in conversation)

**Step 2: Update the Enrichment Matrix section**

Replace the hardcoded Enrichment Matrix with the dynamic routing table from the server registry:

```markdown
## Enrichment Routing (Dynamic)

Routing is determined by `config/mcp_server_registry.json`. The `check-server-health` skill
adjusts routes at session start based on available servers.

### Default Routing Table

| IOC Type | Primary | Secondary | Fallback |
|----------|---------|-----------|----------|
| File Hash | gti | mcp-threatintel | — |
| Domain | gti | mcp-censys, mcp-dnstwist | networksdb-mcp |
| IP Address | gti, mcp-shodan | fastmcp-threatintel, mcp-threatintel | networksdb-mcp |
| URL | gti | mcp-threatintel | — |
| CVE | mcp-nvd | epss-mcp, kev-mcp | vulnerability-intelligence-mcp |
| Threat Actor | gti, feedly | otx-mcp, mcp-security-orkl | mallory-mcp-server |

### Routing Protocol
```
FOR EACH ioc IN enrichment_queue:
  DETERMINE ioc_type
  LOAD routing from adjusted_routing (from check-server-health)

  FOR EACH server IN primary_chain:
    CALL server.enrich(ioc)
    IF success: RECORD result, CONTINUE to secondary for additional context
    IF error: CLASSIFY error, APPLY recovery strategy, TRY next server

  FOR EACH server IN secondary_chain:
    CALL server.enrich(ioc)  # Additional context, not required
    IF success: MERGE with primary results
    IF error: LOG and CONTINUE (secondary failures are non-blocking)

  IF primary_chain returned no results:
    FOR EACH server IN fallback_chain:
      CALL server.enrich(ioc)
      IF success: USE as primary result with caveat
```
```

**Step 3: Add new enrichment protocols for new server types**

Add CVE enrichment, threat actor enrichment, and adjusted IP/domain protocols that reference the new servers.

**Step 4: Commit**

```bash
git add skills/enrich-iocs/SKILL.md
git commit -m "feat: update enrich-iocs with dynamic routing for 23 MCP servers"
```

---

## Task 9: Update monitor-feeds Skill

**Files:**
- Modify: `skills/monitor-feeds/SKILL.md`

**Step 1: Add new intelligence sources**

Update the MCP-Native Collection section to include OTX, ORKL, Mallory, and TI Mindmap HUB as additional collection sources beyond Feedly and GTI.

**Step 2: Add CVE monitoring**

Add a new subsection for CVE feed monitoring using mcp-nvd, kev-mcp, and epss-mcp:

```markdown
### CVE Intelligence Collection
```
CALL mcp-nvd.search_cves(query: "recently_published", days: 7)
CALL kev-mcp.get_recent(days: 7)
CALL epss-mcp.get_high_scores(threshold: 0.5)

FOR EACH cve:
  IF in KEV catalog: priority = P1
  ELIF epss_score > 0.5: priority = P2
  ELSE: priority = P3
  ADD to enrichment_queue
```
```

**Step 3: Commit**

```bash
git add skills/monitor-feeds/SKILL.md
git commit -m "feat: update monitor-feeds with OTX, ORKL, CVE monitoring sources"
```

---

## Task 10: Update AGENT.md Orchestration

**Files:**
- Modify: `AGENT.md`

**Step 1: Update Skill Registry table**

Add all new skills with correct priorities:

| Skill | Priority | Dependencies |
|-------|----------|-------------|
| check-server-health | 0 | None |
| plan-session | 1 | check-server-health |
| monitor-feeds | 2 | plan-session |
| enrich-iocs | 3 | monitor-feeds |
| verify-claims | 4 | enrich-iocs |
| diamond-model-analysis | 5 | verify-claims |
| analysis-competing-hypotheses | 6 | diamond-model |
| generate-report | 7 | diamond-model, ach |
| self-evolving-loop | 8 | All skills |

**Step 2: Update MCP Server Registry table**

Replace the 3-server table with a reference to `config/mcp_server_registry.json` and a summary showing 23 servers across 6 categories.

**Step 3: Update MCP Tool Selection Logic**

Replace the hardcoded tool selection with a reference to the dynamic routing table.

**Step 4: Update Main Execution Loop**

Add `check-server-health` as step 0 before plan-session.

**Step 5: Commit**

```bash
git add AGENT.md
git commit -m "feat: update AGENT.md with 23-server registry and new skill priorities"
```

---

## Task 11: Generate mcp_config.json from Registry

**Files:**
- Create: `scripts/generate_mcp_config.py`
- Modify: `config/mcp_config.json` (regenerated)

**Step 1: Write the generation script**

Create `scripts/generate_mcp_config.py`:

```python
#!/usr/bin/env python3
"""Generate config/mcp_config.json from the server registry."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from lib.config import generate_mcp_config

def main():
    config = generate_mcp_config()
    output_path = Path(__file__).parent.parent / "config" / "mcp_config.json"
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"Generated {output_path} with {len(config['mcpServers'])} servers")

if __name__ == "__main__":
    main()
```

**Step 2: Run it**

Run: `python scripts/generate_mcp_config.py`
Expected: "Generated config/mcp_config.json with 23 servers"

**Step 3: Commit**

```bash
git add scripts/generate_mcp_config.py config/mcp_config.json
git commit -m "feat: add script to generate mcp_config.json from server registry"
```

---

## Task 12: CI/CD Pipeline

**Files:**
- Create: `.github/workflows/test.yml`

**Step 1: Create the workflow**

Create `.github/workflows/test.yml`:

```yaml
name: CTI Agent Tests

on:
  push:
    branches: [main, develop, "phase-*/*"]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run tests
        run: python -m pytest tests/ -v --tb=short

      - name: Validate JSON configs
        run: |
          python -c "import json; json.load(open('config/mcp_server_registry.json'))"
          python -c "import json; json.load(open('config/mcp_config.json'))"
          python -c "import json; json.load(open('config/feeds.json'))"
          python -c "import json; json.load(open('state/skill_versions.json'))"
          python -c "import json; json.load(open('state/processed_guids.json'))"
          python -c "import json; json.load(open('alerts/pending.json'))"

      - name: Verify mcp_config.json matches registry
        run: |
          python scripts/generate_mcp_config.py
          git diff --exit-code config/mcp_config.json || (echo "mcp_config.json out of sync with registry!" && exit 1)
```

**Step 2: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/test.yml
git commit -m "ci: add GitHub Actions test pipeline with JSON validation"
```

---

## Task 13: Project CLAUDE.md

**Files:**
- Create: `CLAUDE.md` (in project root)

**Step 1: Create CLAUDE.md**

```markdown
# CTI Agent Development Instructions

## What This Project Is

CTI Agent is an autonomous threat intelligence agent powered by Claude. It uses SKILL.md files as prompt instructions, MCP servers as data sources, and a self-evolving evaluation loop for quality improvement.

**Key distinction**: AGENT.md is the runtime brain (instructions Claude follows when *running* the agent). CLAUDE.md (this file) tells Claude Code how to *develop* the project.

## Architecture

- **SKILL.md files**: Prompt instructions for each capability (not Python code)
- **MCP servers**: External tools Claude calls for live data (configured in config/mcp_server_registry.json)
- **lib/**: Python utilities for config loading, logging, health checks
- **evaluation/**: Python graders for output quality assessment
- **state/**: JSON files for session persistence
- **config/**: Server registry, feeds, environment templates

## Development Conventions

### Adding a New MCP Server
1. Add entry to `config/mcp_server_registry.json`
2. Add routing entries if the server handles IOC types
3. Run `python scripts/generate_mcp_config.py` to regenerate mcp_config.json
4. Add tests in `tests/test_config.py`
5. Update `config/.env.template` if API key required

### Adding a New Skill
1. Create `skills/{skill-name}/SKILL.md` following the existing SKILL.md format
2. Add to AGENT.md skill registry with correct priority and dependencies
3. Add entry to `state/skill_versions.json`
4. Update AGENT.md execution loop if the skill changes workflow order

### Testing
- Run: `python -m pytest tests/ -v`
- JSON validation: All config/state files must be valid JSON
- Evaluation graders: `python evaluation/run_evaluation.py <source> <output>`

### Git Workflow
- `main`: Stable releases (tagged vX.Y.Z)
- `develop`: Integration branch
- `phase-N/*`: Feature branches per implementation phase
- Commit messages: `feat:`, `fix:`, `ci:`, `docs:` prefixes

## Current Phase: Phase 1 (MCP Server Expansion)

See `docs/plans/2026-02-16-jtia-v2-design.md` for full design.
See `docs/plans/2026-02-16-jtia-v2-phase1-plan.md` for implementation plan.
```

**Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add project CLAUDE.md with development conventions"
```

---

## Task 14: Final Integration Test

**Files:**
- Create: `tests/test_integration.py`

**Step 1: Write integration test**

```python
#!/usr/bin/env python3
"""Integration tests verifying Phase 1 components work together."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).parent.parent


class TestPhase1Integration:

    def test_registry_config_and_routing_consistent(self):
        """All servers referenced in routing exist in the server list."""
        from lib.config import load_server_registry
        registry = load_server_registry()
        server_names = {s["name"] for s in registry["servers"]}
        for ioc_type, chains in registry["routing"].items():
            for chain_name in ("primary", "secondary", "fallback"):
                for server in chains[chain_name]:
                    assert server in server_names, (
                        f"Routing references '{server}' for {ioc_type}.{chain_name} "
                        f"but it's not in the server list"
                    )

    def test_mcp_config_matches_registry(self):
        """Generated mcp_config.json has all registry servers."""
        from lib.config import generate_mcp_config, load_server_registry
        registry = load_server_registry()
        config = generate_mcp_config()
        registry_names = {s["name"] for s in registry["servers"]}
        config_names = set(config["mcpServers"].keys())
        assert registry_names == config_names

    def test_health_check_with_no_keys(self):
        """Health check works with zero API keys set."""
        from lib.health_check import run_health_check
        with patch.dict("os.environ", {}, clear=True):
            report = run_health_check()
            assert report["total_servers"] == 23
            assert report["available_count"] >= 13  # 13 servers need no key
            assert report["unavailable_count"] <= 10

    def test_all_skills_have_skill_md(self):
        """Every directory in skills/ has a SKILL.md file."""
        skills_dir = PROJECT_ROOT / "skills"
        for skill_dir in skills_dir.iterdir():
            if skill_dir.is_dir():
                skill_file = skill_dir / "SKILL.md"
                assert skill_file.exists(), f"Missing SKILL.md in {skill_dir.name}"

    def test_skill_versions_tracks_all_skills(self):
        """skill_versions.json has entries for all skills."""
        skills_dir = PROJECT_ROOT / "skills"
        with open(PROJECT_ROOT / "state" / "skill_versions.json") as f:
            versions = json.load(f)
        skill_dirs = {d.name for d in skills_dir.iterdir() if d.is_dir()}
        tracked = set(versions["skills"].keys())
        missing = skill_dirs - tracked
        assert not missing, f"Skills not tracked in skill_versions.json: {missing}"
```

**Step 2: Run all tests**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add Phase 1 integration tests"
```

---

## Task 15: Tag Phase 1 Release

**Step 1: Run full test suite one final time**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS

**Step 2: Tag the release**

```bash
git tag -a v2.1.0 -m "CTI Agent v2.1.0 - Phase 1: MCP Server Expansion

- 23 MCP servers (20 new, all open-source)
- Dynamic IOC routing with fallback chains
- Server health check skill
- Plan session skill
- Structured logging with error classification
- API key management with graceful degradation
- CI/CD pipeline with JSON validation
- Project CLAUDE.md"
```

---

## Summary

| Task | Description | Files | Tests |
|------|-------------|-------|-------|
| 1 | Server registry + scaffolding | 5 new | 6 tests |
| 2 | Updated .env templates | 2 modified | — |
| 3 | Config loader utility | 2 new | 7 tests |
| 4 | Structured logging | 2 new | 12 tests |
| 5 | Health check utility | 2 new | 4 tests |
| 6 | check-server-health skill | 1 new, 2 modified | — |
| 7 | plan-session skill | 1 new, 2 modified | — |
| 8 | Update enrich-iocs routing | 1 modified | — |
| 9 | Update monitor-feeds sources | 1 modified | — |
| 10 | Update AGENT.md orchestration | 1 modified | — |
| 11 | Generate mcp_config.json script | 2 new/modified | — |
| 12 | CI/CD pipeline | 1 new | — |
| 13 | Project CLAUDE.md | 1 new | — |
| 14 | Integration tests | 1 new | 5 tests |
| 15 | Tag v2.1.0 release | — | Full suite |

**Total: 15 tasks, ~34 tests, 15 commits**

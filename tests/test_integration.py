"""Integration tests for JTIA v2.1.0 Phase 1.

Validates cross-cutting concerns: routing consistency, config sync,
health check behavior, skill coverage, and version tracking.
"""

import json
import os
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
SKILLS_DIR = PROJECT_ROOT / "skills"


@pytest.fixture
def registry():
    with open(CONFIG_DIR / "mcp_server_registry.json") as f:
        return json.load(f)


@pytest.fixture
def mcp_config():
    with open(CONFIG_DIR / "mcp_config.json") as f:
        return json.load(f)


class TestRoutingConsistency:
    """Every server referenced in routing must exist in servers list."""

    def test_all_routing_servers_exist(self, registry):
        server_names = {s["name"] for s in registry["servers"]}
        routing = registry["routing"]

        missing = []
        for ioc_type, chains in routing.items():
            for chain_name in ("primary", "secondary", "fallback"):
                for server in chains.get(chain_name, []):
                    if server not in server_names:
                        missing.append(f"{ioc_type}.{chain_name}: {server}")

        assert not missing, f"Routing references unknown servers: {missing}"

    def test_all_ioc_types_have_primary(self, registry):
        routing = registry["routing"]
        for ioc_type, chains in routing.items():
            assert len(chains.get("primary", [])) > 0, (
                f"IOC type '{ioc_type}' has no primary routing chain"
            )


class TestMcpConfigSync:
    """mcp_config.json must match mcp_server_registry.json servers."""

    def test_server_count_matches(self, registry, mcp_config):
        registry_names = {s["name"] for s in registry["servers"]}
        config_names = set(mcp_config.get("mcpServers", {}).keys())
        assert registry_names == config_names, (
            f"Registry/config mismatch. "
            f"In registry only: {registry_names - config_names}. "
            f"In config only: {config_names - registry_names}"
        )


class TestHealthCheckNoKeys:
    """Health check utility works when no API keys are set."""

    def test_health_report_with_empty_env(self, monkeypatch):
        from lib.health_check import run_health_check

        # Clear all API key env vars so health check runs in degraded mode
        for key in ("VT_API_KEY", "FEEDLY_ACCESS_TOKEN", "SHODAN_API_KEY",
                     "OTX_API_KEY", "ABUSEIPDB_API_KEY", "CENSYS_API_ID",
                     "CENSYS_API_SECRET", "MALLORY_API_KEY"):
            monkeypatch.delenv(key, raising=False)

        report = run_health_check()
        assert "total_servers" in report
        assert report["total_servers"] >= 23
        assert "missing_keys" in report
        assert isinstance(report["degraded_capabilities"], list)
        assert report["unavailable_count"] > 0  # No keys set = some unavailable


class TestSkillCoverage:
    """Every skill directory must contain a SKILL.md file."""

    def test_all_skills_have_skill_md(self):
        missing = []
        for skill_dir in SKILLS_DIR.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("."):
                skill_file = skill_dir / "SKILL.md"
                if not skill_file.exists():
                    missing.append(skill_dir.name)

        assert not missing, f"Skills missing SKILL.md: {missing}"

    def test_skill_md_has_frontmatter(self):
        for skill_dir in SKILLS_DIR.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("."):
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists():
                    content = skill_file.read_text()
                    assert content.startswith("---"), (
                        f"{skill_dir.name}/SKILL.md missing frontmatter header"
                    )


class TestVersionTracking:
    """Version strings are consistent."""

    def test_agent_md_version_is_2_1_0(self):
        agent_md = (PROJECT_ROOT / "AGENT.md").read_text()
        assert "**Version**: 2.1.0" in agent_md

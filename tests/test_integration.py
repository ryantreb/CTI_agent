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

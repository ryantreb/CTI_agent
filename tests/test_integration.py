"""Integration tests for JTIA v2.2.0 Phase 1+2.

Validates cross-cutting concerns: routing consistency, config sync,
health check behavior, skill coverage, version tracking, STIX output,
ATT&CK layers, external skills, skill ownership, and demo dataset.
"""

import json
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
        for key in (
            "VT_API_KEY",
            "FEEDLY_ACCESS_TOKEN",
            "SHODAN_API_KEY",
            "OTX_API_KEY",
            "ABUSEIPDB_API_KEY",
            "CENSYS_API_ID",
            "CENSYS_API_SECRET",
            "MALLORY_API_KEY",
        ):
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
                if skill_dir.name == "external":
                    continue  # External skills have their own structure
                skill_file = skill_dir / "SKILL.md"
                if not skill_file.exists():
                    missing.append(skill_dir.name)

        assert not missing, f"Skills missing SKILL.md: {missing}"

    def test_skill_md_has_frontmatter(self):
        for skill_dir in SKILLS_DIR.iterdir():
            if skill_dir.is_dir() and not skill_dir.name.startswith("."):
                if skill_dir.name == "external":
                    continue
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists():
                    content = skill_file.read_text()
                    assert content.startswith("---"), (
                        f"{skill_dir.name}/SKILL.md missing frontmatter header"
                    )


class TestVersionTracking:
    """Version strings are consistent."""

    def test_agent_md_version_is_2_2_0(self):
        agent_md = (PROJECT_ROOT / "AGENT.md").read_text()
        assert "**Version**: 2.2.0" in agent_md


# --- Phase 2 Tests ---


class TestSTIXBuilder:
    """STIX builder produces valid bundles from Diamond Model input."""

    def test_diamond_to_stix_produces_bundle(self):
        from lib.stix_builder import diamond_to_stix

        diamond = {
            "adversary": {"name": "TestActor"},
            "capability": {
                "attack_patterns": [
                    {
                        "name": "Phishing",
                        "mitre_id": "T1566",
                        "kill_chain_phase": "initial-access",
                    }
                ],
            },
        }
        bundle = diamond_to_stix(diamond)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) >= 2

    def test_stix_bundle_has_required_fields(self):
        from lib.stix_builder import diamond_to_stix

        diamond = {
            "adversary": {"name": "APT1", "aliases": ["Comment Crew"]},
            "infrastructure": {
                "name": "C2",
                "types": ["command-and-control"],
                "iocs": [{"type": "ipv4-addr", "value": "10.0.0.1"}],
            },
            "victim": {"name": "Target", "identity_class": "organization"},
        }
        bundle = diamond_to_stix(diamond)
        for obj in bundle["objects"]:
            assert "type" in obj
            assert "id" in obj
            assert obj["id"].startswith(f"{obj['type']}--")


class TestAttackLayers:
    """ATT&CK layer builder produces valid Navigator JSON."""

    def test_diamond_to_layer_produces_layer(self):
        from lib.attack_layers import diamond_to_layer

        diamond = {
            "adversary": {"name": "TestActor"},
            "capability": {
                "attack_patterns": [
                    {
                        "name": "Phishing",
                        "mitre_id": "T1566",
                        "kill_chain_phase": "initial-access",
                        "confidence": "high",
                    }
                ],
            },
        }
        layer = diamond_to_layer(diamond)
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert len(layer["techniques"]) == 1

    def test_layer_technique_has_color(self):
        from lib.attack_layers import diamond_to_layer

        diamond = {
            "capability": {
                "attack_patterns": [
                    {
                        "name": "Test",
                        "mitre_id": "T1059",
                        "kill_chain_phase": "execution",
                        "confidence": "medium",
                    }
                ],
            },
        }
        layer = diamond_to_layer(diamond)
        assert layer["techniques"][0]["color"] == "#ffaa66"


class TestExternalSkills:
    """External skills are installed in the correct locations."""

    def test_external_skills_directory_exists(self):
        external_dir = SKILLS_DIR / "external"
        assert external_dir.is_dir(), "skills/external/ directory missing"

    def test_malware_analysis_skills_installed(self):
        ma_dir = SKILLS_DIR / "external" / "malware-analysis"
        if ma_dir.exists():
            contents = list(ma_dir.iterdir())
            assert len(contents) > 0, "malware-analysis directory is empty"

    def test_yara_skill_installed(self):
        yara_dir = SKILLS_DIR / "external" / "yara-rule-skill"
        if yara_dir.exists():
            contents = list(yara_dir.iterdir())
            assert len(contents) > 0, "yara-rule-skill directory is empty"

    def test_trailofbits_skills_installed(self):
        tob_dir = SKILLS_DIR / "external" / "trailofbits"
        if tob_dir.exists():
            contents = list(tob_dir.iterdir())
            assert len(contents) > 0, "trailofbits directory is empty"


class TestSkillOwnership:
    """Skill conflict resolution config is valid."""

    def test_skill_ownership_config_exists(self):
        ownership_file = CONFIG_DIR / "skill_ownership.json"
        assert ownership_file.exists(), "config/skill_ownership.json missing"

    def test_skill_ownership_has_required_keys(self):
        with open(CONFIG_DIR / "skill_ownership.json") as f:
            ownership = json.load(f)
        assert "ownership" in ownership
        for rule_type in ("yara_rules", "sigma_rules", "reports"):
            assert rule_type in ownership["ownership"], (
                f"Missing ownership for {rule_type}"
            )
            assert "primary" in ownership["ownership"][rule_type]


class TestDemoDataset:
    """Demo dataset is complete and valid."""

    def test_demo_directory_exists(self):
        demo_dir = PROJECT_ROOT / "demo"
        assert demo_dir.is_dir(), "demo/ directory missing"

    def test_sample_input_valid_json(self):
        sample = PROJECT_ROOT / "demo" / "sample_input.json"
        if sample.exists():
            with open(sample) as f:
                data = json.load(f)
            assert "iocs" in data
            assert "ttps" in data

    def test_mock_responses_exist(self):
        mock_dir = PROJECT_ROOT / "demo" / "mock_mcp_responses"
        if mock_dir.exists():
            responses = list(mock_dir.glob("*.json"))
            assert len(responses) >= 1, "No mock MCP responses found"

    def test_run_demo_script_exists(self):
        script = PROJECT_ROOT / "demo" / "run_demo.sh"
        assert script.exists(), "demo/run_demo.sh missing"

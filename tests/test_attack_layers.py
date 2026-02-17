"""Tests for ATT&CK Navigator layer generation."""

import json


from lib.attack_layers import (
    build_attack_layer,
    technique_entry,
    confidence_to_color,
    diamond_to_layer,
)


CONFIDENCE_COLORS = {
    "high": "#ff6666",
    "medium": "#ffaa66",
    "low": "#ffff66",
}


class TestTechniqueEntry:
    def test_basic_technique(self):
        entry = technique_entry(
            technique_id="T1566.001",
            tactic="initial-access",
            confidence="high",
            comment="Spearphishing observed",
            source="GTI analysis",
        )
        assert entry["techniqueID"] == "T1566.001"
        assert entry["tactic"] == "initial-access"
        assert entry["color"] == "#ff6666"
        assert entry["score"] == 85

    def test_medium_confidence(self):
        entry = technique_entry(
            technique_id="T1059",
            tactic="execution",
            confidence="medium",
        )
        assert entry["color"] == "#ffaa66"
        assert entry["score"] == 50

    def test_low_confidence(self):
        entry = technique_entry(
            technique_id="T1071",
            tactic="command-and-control",
            confidence="low",
        )
        assert entry["color"] == "#ffff66"
        assert entry["score"] == 25


class TestConfidenceToColor:
    def test_all_levels(self):
        assert confidence_to_color("high") == "#ff6666"
        assert confidence_to_color("medium") == "#ffaa66"
        assert confidence_to_color("low") == "#ffff66"

    def test_unknown_defaults_to_yellow(self):
        assert confidence_to_color("unknown") == "#ffff66"


class TestBuildAttackLayer:
    def test_layer_structure(self):
        techniques = [
            technique_entry("T1566.001", "initial-access", "high"),
        ]
        layer = build_attack_layer(
            name="Test Campaign",
            description="Test layer",
            techniques=techniques,
        )
        assert layer["name"] == "Test Campaign"
        assert layer["versions"]["layer"] == "4.5"
        assert layer["domain"] == "enterprise-attack"
        assert len(layer["techniques"]) == 1

    def test_layer_is_valid_json(self):
        techniques = [technique_entry("T1059", "execution", "medium")]
        layer = build_attack_layer("Test", "Desc", techniques)
        serialized = json.dumps(layer)
        parsed = json.loads(serialized)
        assert parsed["domain"] == "enterprise-attack"


class TestDiamondToLayer:
    def test_diamond_with_attack_patterns(self):
        diamond = {
            "adversary": {"name": "APT29"},
            "capability": {
                "attack_patterns": [
                    {
                        "name": "Spearphishing Attachment",
                        "mitre_id": "T1566.001",
                        "kill_chain_phase": "initial-access",
                        "confidence": "high",
                    },
                    {
                        "name": "Command and Scripting Interpreter",
                        "mitre_id": "T1059",
                        "kill_chain_phase": "execution",
                        "confidence": "medium",
                    },
                ],
            },
        }
        layer = diamond_to_layer(diamond, report_guid="test-guid")
        assert layer["name"] == "APT29 - CTI Agent Analysis"
        assert len(layer["techniques"]) == 2

    def test_diamond_minimal(self):
        diamond = {
            "capability": {
                "attack_patterns": [
                    {
                        "name": "Phishing",
                        "mitre_id": "T1566",
                        "kill_chain_phase": "initial-access",
                    },
                ],
            },
        }
        layer = diamond_to_layer(diamond)
        assert len(layer["techniques"]) == 1

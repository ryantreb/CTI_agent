"""Tests for STIX 2.1 bundle builder."""

import json


from lib.stix_builder import (
    build_stix_bundle,
    create_threat_actor,
    create_infrastructure,
    create_malware,
    create_attack_pattern,
    create_identity,
    create_indicator,
    create_relationship,
    diamond_to_stix,
)


class TestSTIXObjectCreation:
    """Individual STIX SDO/SRO creation."""

    def test_create_threat_actor(self):
        actor = create_threat_actor(
            name="APT29",
            aliases=["Cozy Bear", "The Dukes"],
            description="Russian state-sponsored group",
            sophistication="expert",
        )
        assert actor["type"] == "threat-actor"
        assert actor["name"] == "APT29"
        assert "Cozy Bear" in actor["aliases"]
        assert actor["id"].startswith("threat-actor--")

    def test_create_infrastructure(self):
        infra = create_infrastructure(
            name="C2 Server 192.168.1.1",
            infrastructure_types=["command-and-control"],
            description="Primary C2 node",
        )
        assert infra["type"] == "infrastructure"
        assert "command-and-control" in infra["infrastructure_types"]

    def test_create_indicator_ip(self):
        indicator = create_indicator(
            name="Malicious IP",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
        )
        assert indicator["type"] == "indicator"
        assert indicator["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert indicator["pattern_type"] == "stix"

    def test_create_indicator_hash(self):
        indicator = create_indicator(
            name="Malicious File Hash",
            pattern="[file:hashes.'SHA-256' = 'abc123']",
            pattern_type="stix",
            indicator_types=["malicious-activity"],
        )
        assert "SHA-256" in indicator["pattern"]

    def test_create_malware(self):
        mal = create_malware(
            name="SUNBURST",
            malware_types=["backdoor"],
            is_family=True,
            description="Supply chain backdoor",
        )
        assert mal["type"] == "malware"
        assert mal["is_family"] is True

    def test_create_attack_pattern(self):
        ap = create_attack_pattern(
            name="Spearphishing Attachment",
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1566.001",
                }
            ],
            kill_chain_phases=[
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access",
                }
            ],
        )
        assert ap["type"] == "attack-pattern"
        assert ap["external_references"][0]["external_id"] == "T1566.001"

    def test_create_identity(self):
        victim = create_identity(
            name="Acme Corp",
            identity_class="organization",
            sectors=["technology"],
        )
        assert victim["type"] == "identity"
        assert victim["identity_class"] == "organization"

    def test_create_relationship(self):
        rel = create_relationship(
            source_ref="threat-actor--aaa",
            target_ref="malware--bbb",
            relationship_type="uses",
        )
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "uses"


class TestBundleBuilding:
    """Full bundle assembly."""

    def test_build_stix_bundle_valid(self):
        actor = create_threat_actor(name="TestActor")
        mal = create_malware(
            name="TestMalware", malware_types=["trojan"], is_family=False
        )
        bundle = build_stix_bundle([actor, mal])

        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) == 2

    def test_bundle_is_valid_json(self):
        actor = create_threat_actor(name="TestActor")
        bundle = build_stix_bundle([actor])
        serialized = json.dumps(bundle)
        parsed = json.loads(serialized)
        assert parsed["type"] == "bundle"


class TestDiamondToSTIX:
    """Diamond Model -> STIX 2.1 mapping."""

    def test_diamond_to_stix_full(self):
        diamond = {
            "adversary": {
                "name": "APT29",
                "aliases": ["Cozy Bear"],
                "description": "Russian SVR",
                "sophistication": "expert",
            },
            "infrastructure": {
                "name": "C2 cluster",
                "types": ["command-and-control"],
                "iocs": [
                    {"type": "ipv4-addr", "value": "1.2.3.4"},
                    {"type": "domain-name", "value": "evil.com"},
                ],
            },
            "capability": {
                "malware": {
                    "name": "SUNBURST",
                    "types": ["backdoor"],
                    "is_family": True,
                },
                "attack_patterns": [
                    {
                        "name": "Supply Chain Compromise",
                        "mitre_id": "T1195.002",
                        "kill_chain_phase": "initial-access",
                    }
                ],
            },
            "victim": {
                "name": "SolarWinds",
                "identity_class": "organization",
                "sectors": ["technology"],
            },
        }

        bundle = diamond_to_stix(diamond)
        types_in_bundle = {obj["type"] for obj in bundle["objects"]}

        assert "threat-actor" in types_in_bundle
        assert "infrastructure" in types_in_bundle
        assert "malware" in types_in_bundle
        assert "attack-pattern" in types_in_bundle
        assert "identity" in types_in_bundle
        assert "indicator" in types_in_bundle
        assert "relationship" in types_in_bundle

    def test_diamond_to_stix_minimal(self):
        diamond = {
            "adversary": {"name": "Unknown Actor"},
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

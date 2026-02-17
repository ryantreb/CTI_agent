# CTI Agent v2.2.0 Phase 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add STIX 2.1 native output, ATT&CK Navigator layer generation, external security skills integration, skill conflict resolution, and a demo dataset to CTI Agent.

**Architecture:** Phase 2 adds two new output skills (produce-stix-bundle, produce-attack-layers) backed by Python libraries, integrates 12 external skills from three sources with conflict resolution, and provides a demo dataset for end-to-end testing without live APIs.

**Tech Stack:** Python 3.12+, pytest, stix2 library, MITRE ATT&CK Navigator v4.5 JSON format, SKILL.md prompt orchestration

---

### Task 1: STIX 2.1 Builder Library — Tests

**Files:**
- Create: `tests/test_stix_builder.py`

**Step 1: Write failing tests for STIX builder**

```python
"""Tests for STIX 2.1 bundle builder."""
import json
from datetime import datetime, timezone

import pytest

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
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": "T1566.001",
            }],
            kill_chain_phases=[{
                "kill_chain_name": "mitre-attack",
                "phase_name": "initial-access",
            }],
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
        mal = create_malware(name="TestMalware", malware_types=["trojan"], is_family=False)
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
    """Diamond Model → STIX 2.1 mapping."""

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
                "malware": {"name": "SUNBURST", "types": ["backdoor"], "is_family": True},
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
                    {"name": "Phishing", "mitre_id": "T1566", "kill_chain_phase": "initial-access"}
                ],
            },
        }
        bundle = diamond_to_stix(diamond)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) >= 2
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_stix_builder.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.stix_builder'`

**Step 3: Commit**

```bash
git add tests/test_stix_builder.py
git commit -m "test: add STIX 2.1 builder tests (red phase)"
```

---

### Task 2: STIX 2.1 Builder Library — Implementation

**Files:**
- Create: `lib/stix_builder.py`

**Step 1: Implement STIX builder**

```python
"""STIX 2.1 bundle builder for Diamond Model output."""
import uuid
from datetime import datetime, timezone


def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def create_threat_actor(
    name: str,
    *,
    aliases: list[str] | None = None,
    description: str = "",
    sophistication: str = "",
) -> dict:
    obj = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": _stix_id("threat-actor"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name,
    }
    if aliases:
        obj["aliases"] = aliases
    if description:
        obj["description"] = description
    if sophistication:
        obj["sophistication"] = sophistication
    return obj


def create_infrastructure(
    name: str,
    *,
    infrastructure_types: list[str] | None = None,
    description: str = "",
) -> dict:
    obj = {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": _stix_id("infrastructure"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name,
    }
    if infrastructure_types:
        obj["infrastructure_types"] = infrastructure_types
    if description:
        obj["description"] = description
    return obj


def create_malware(
    name: str,
    *,
    malware_types: list[str] | None = None,
    is_family: bool = False,
    description: str = "",
) -> dict:
    obj = {
        "type": "malware",
        "spec_version": "2.1",
        "id": _stix_id("malware"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name,
        "is_family": is_family,
    }
    if malware_types:
        obj["malware_types"] = malware_types
    if description:
        obj["description"] = description
    return obj


def create_attack_pattern(
    name: str,
    *,
    external_references: list[dict] | None = None,
    kill_chain_phases: list[dict] | None = None,
) -> dict:
    obj = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _stix_id("attack-pattern"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name,
    }
    if external_references:
        obj["external_references"] = external_references
    if kill_chain_phases:
        obj["kill_chain_phases"] = kill_chain_phases
    return obj


def create_identity(
    name: str,
    *,
    identity_class: str = "unknown",
    sectors: list[str] | None = None,
) -> dict:
    obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name,
        "identity_class": identity_class,
    }
    if sectors:
        obj["sectors"] = sectors
    return obj


def create_indicator(
    name: str,
    *,
    pattern: str,
    pattern_type: str = "stix",
    indicator_types: list[str] | None = None,
) -> dict:
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": name,
        "pattern": pattern,
        "pattern_type": pattern_type,
        "valid_from": _now_iso(),
    }
    if indicator_types:
        obj["indicator_types"] = indicator_types
    return obj


def create_relationship(
    source_ref: str,
    target_ref: str,
    relationship_type: str,
) -> dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _stix_id("relationship"),
        "created": _now_iso(),
        "modified": _now_iso(),
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }


def _ioc_to_pattern(ioc: dict) -> str:
    ioc_type = ioc["type"]
    value = ioc["value"]
    patterns = {
        "ipv4-addr": f"[ipv4-addr:value = '{value}']",
        "ipv6-addr": f"[ipv6-addr:value = '{value}']",
        "domain-name": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "sha-256": f"[file:hashes.'SHA-256' = '{value}']",
        "sha-1": f"[file:hashes.'SHA-1' = '{value}']",
        "md5": f"[file:hashes.MD5 = '{value}']",
    }
    return patterns.get(ioc_type, f"[{ioc_type}:value = '{value}']")


def build_stix_bundle(objects: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }


def diamond_to_stix(diamond: dict) -> dict:
    objects = []
    refs = {}

    if adv := diamond.get("adversary"):
        actor = create_threat_actor(
            name=adv["name"],
            aliases=adv.get("aliases"),
            description=adv.get("description", ""),
            sophistication=adv.get("sophistication", ""),
        )
        objects.append(actor)
        refs["adversary"] = actor["id"]

    if infra := diamond.get("infrastructure"):
        infra_obj = create_infrastructure(
            name=infra["name"],
            infrastructure_types=infra.get("types"),
        )
        objects.append(infra_obj)
        refs["infrastructure"] = infra_obj["id"]

        for ioc in infra.get("iocs", []):
            indicator = create_indicator(
                name=f"IOC: {ioc['value']}",
                pattern=_ioc_to_pattern(ioc),
                indicator_types=["malicious-activity"],
            )
            objects.append(indicator)
            objects.append(create_relationship(
                indicator["id"], infra_obj["id"], "indicates",
            ))

    if cap := diamond.get("capability"):
        if mal_info := cap.get("malware"):
            mal = create_malware(
                name=mal_info["name"],
                malware_types=mal_info.get("types"),
                is_family=mal_info.get("is_family", False),
            )
            objects.append(mal)
            refs["malware"] = mal["id"]

        for ap_info in cap.get("attack_patterns", []):
            ap = create_attack_pattern(
                name=ap_info["name"],
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": ap_info["mitre_id"],
                }],
                kill_chain_phases=[{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": ap_info.get("kill_chain_phase", ""),
                }],
            )
            objects.append(ap)

    if victim := diamond.get("victim"):
        identity = create_identity(
            name=victim["name"],
            identity_class=victim.get("identity_class", "unknown"),
            sectors=victim.get("sectors"),
        )
        objects.append(identity)
        refs["victim"] = identity["id"]

    if "adversary" in refs and "malware" in refs:
        objects.append(create_relationship(refs["adversary"], refs["malware"], "uses"))
    if "adversary" in refs and "infrastructure" in refs:
        objects.append(create_relationship(refs["adversary"], refs["infrastructure"], "uses"))
    if "adversary" in refs and "victim" in refs:
        objects.append(create_relationship(refs["adversary"], refs["victim"], "targets"))
    if "malware" in refs and "victim" in refs:
        objects.append(create_relationship(refs["malware"], refs["victim"], "targets"))

    return build_stix_bundle(objects)
```

**Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_stix_builder.py -q`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add lib/stix_builder.py
git commit -m "feat: add STIX 2.1 bundle builder library"
```

---

### Task 3: produce-stix-bundle SKILL.md

**Files:**
- Create: `skills/produce-stix-bundle/SKILL.md`

**Step 1: Create skill directory and SKILL.md**

```markdown
---
name: produce-stix-bundle
description: Transform Diamond Model analysis output into STIX 2.1 bundles. Use after diamond-model-analysis to produce machine-readable threat intelligence in OASIS STIX 2.1 format for sharing with SIEMs, TIPs, and partner organizations.
---

# Produce STIX Bundle Skill

## Purpose

Convert Diamond Model analysis into STIX 2.1 bundles for machine-to-machine intelligence sharing.

## Prerequisites

- Completed Diamond Model analysis output (from `diamond-model-analysis` skill)
- IOC enrichment data (from `enrich-iocs` skill)

## Mapping: Diamond Model → STIX 2.1

| Diamond Element | STIX 2.1 Object(s) |
|----------------|---------------------|
| Adversary | `threat-actor` SDO + `intrusion-set` SDO (if campaign identified) |
| Infrastructure | `infrastructure` SDO + `indicator` SDOs (one per IOC) |
| Capability | `malware` SDO + `attack-pattern` SDOs (from ATT&CK mapping) |
| Victim | `identity` SDO |
| Relationships | `relationship` SROs (uses, targets, indicates, attributed-to) |
| Kill Chain | `kill-chain-phase` embedded in attack-pattern SDOs |

## Indicator Pattern Syntax

Use STIX Patterning Language:

```
IP:     [ipv4-addr:value = '1.2.3.4']
Domain: [domain-name:value = 'evil.com']
Hash:   [file:hashes.'SHA-256' = 'abc123...']
URL:    [url:value = 'https://evil.com/payload']
Email:  [email-addr:value = 'phish@evil.com']
```

## Execution Protocol

```
THOUGHT: I have Diamond Model analysis output. I need to produce a STIX 2.1 bundle.

ACTION: Extract all Diamond Model elements from analysis output
OBSERVATION: Identified adversary, infrastructure, capability, victim elements

ACTION: For each Diamond element, create corresponding STIX SDOs:
  1. Adversary → threat-actor (always) + intrusion-set (if campaign)
  2. Infrastructure → infrastructure + indicator per IOC
  3. Capability → malware + attack-pattern per TTP
  4. Victim → identity

ACTION: Create STIX SROs linking objects:
  - threat-actor USES malware
  - threat-actor USES infrastructure
  - threat-actor TARGETS identity (victim)
  - indicator INDICATES infrastructure
  - malware TARGETS identity (victim)
  - attack-pattern (kill chain phases embedded)

ACTION: Assemble bundle and validate
OBSERVATION: Bundle contains N SDOs and M SROs

ACTION: Save to reports/{guid}_stix_bundle.json

CONCLUSION: STIX 2.1 bundle produced with {N} objects
```

## Confidence Mapping

Map ICD 203 confidence to STIX confidence scores (0-100):

| ICD 203 Term | STIX Score |
|-------------|-----------|
| Almost certain | 95 |
| Highly likely | 85 |
| Likely | 70 |
| Roughly even chance | 50 |
| Unlikely | 30 |
| Highly unlikely | 15 |
| Remote possibility | 5 |

## Validation

After generating the bundle:
1. Verify all object IDs follow STIX 2.1 format (`type--uuid`)
2. Verify all relationships reference valid source/target IDs
3. Verify indicator patterns use valid STIX Patterning Language
4. Cross-reference with TI Mindmap HUB MCP if available (validation, not replacement)

## Output

- **File**: `reports/{guid}_stix_bundle.json`
- **Format**: STIX 2.1 Bundle JSON
- **Log**: Record bundle creation in `logs/{date}.jsonl`
```

**Step 2: Verify SKILL.md has frontmatter**

Run: `head -3 skills/produce-stix-bundle/SKILL.md`
Expected: Starts with `---`

**Step 3: Commit**

```bash
git add skills/produce-stix-bundle/SKILL.md
git commit -m "feat: add produce-stix-bundle skill"
```

---

### Task 4: ATT&CK Navigator Layer Library — Tests

**Files:**
- Create: `tests/test_attack_layers.py`

**Step 1: Write failing tests for ATT&CK layer builder**

```python
"""Tests for ATT&CK Navigator layer generation."""
import json

import pytest

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
                    {"name": "Phishing", "mitre_id": "T1566", "kill_chain_phase": "initial-access"},
                ],
            },
        }
        layer = diamond_to_layer(diamond)
        assert len(layer["techniques"]) == 1
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_attack_layers.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.attack_layers'`

**Step 3: Commit**

```bash
git add tests/test_attack_layers.py
git commit -m "test: add ATT&CK Navigator layer tests (red phase)"
```

---

### Task 5: ATT&CK Navigator Layer Library — Implementation

**Files:**
- Create: `lib/attack_layers.py`

**Step 1: Implement ATT&CK layer builder**

```python
"""ATT&CK Navigator layer generation from Diamond Model output."""


CONFIDENCE_COLORS = {
    "high": "#ff6666",
    "medium": "#ffaa66",
    "low": "#ffff66",
}

CONFIDENCE_SCORES = {
    "high": 85,
    "medium": 50,
    "low": 25,
}


def confidence_to_color(confidence: str) -> str:
    return CONFIDENCE_COLORS.get(confidence.lower(), "#ffff66")


def technique_entry(
    technique_id: str,
    tactic: str,
    confidence: str,
    *,
    comment: str = "",
    source: str = "",
) -> dict:
    entry = {
        "techniqueID": technique_id,
        "tactic": tactic,
        "color": confidence_to_color(confidence),
        "score": CONFIDENCE_SCORES.get(confidence.lower(), 25),
        "enabled": True,
        "metadata": [
            {"name": "confidence", "value": confidence},
        ],
    }
    if comment:
        entry["comment"] = comment
    if source:
        entry["metadata"].append({"name": "source", "value": source})
    return entry


def build_attack_layer(
    name: str,
    description: str,
    techniques: list[dict],
    *,
    domain: str = "enterprise-attack",
) -> dict:
    return {
        "name": name,
        "versions": {"layer": "4.5", "attack": "15"},
        "domain": domain,
        "description": description,
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffff66", "#ffaa66", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
    }


def diamond_to_layer(diamond: dict, *, report_guid: str = "") -> dict:
    adversary_name = diamond.get("adversary", {}).get("name", "Unknown")
    layer_name = f"{adversary_name} - CTI Agent Analysis"

    techniques = []
    for ap in diamond.get("capability", {}).get("attack_patterns", []):
        confidence = ap.get("confidence", "low")
        techniques.append(technique_entry(
            technique_id=ap["mitre_id"],
            tactic=ap.get("kill_chain_phase", ""),
            confidence=confidence,
            comment=ap.get("name", ""),
        ))

    description = f"Auto-generated by CTI Agent from Diamond Model analysis"
    if report_guid:
        description += f" (report: {report_guid})"

    return build_attack_layer(
        name=layer_name,
        description=description,
        techniques=techniques,
    )
```

**Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_attack_layers.py -q`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add lib/attack_layers.py
git commit -m "feat: add ATT&CK Navigator layer builder library"
```

---

### Task 6: produce-attack-layers SKILL.md

**Files:**
- Create: `skills/produce-attack-layers/SKILL.md`

**Step 1: Create skill directory and SKILL.md**

```markdown
---
name: produce-attack-layers
description: Generate ATT&CK Navigator layer JSON files from Diamond Model analysis output. Use after diamond-model-analysis to produce visual technique coverage maps with confidence-based coloring for ATT&CK Navigator.
---

# Produce ATT&CK Layers Skill

## Purpose

Auto-generate ATT&CK Navigator layer files from analysis output for visual technique coverage mapping.

## Prerequisites

- Completed Diamond Model analysis (from `diamond-model-analysis` skill)
- ATT&CK technique IDs mapped in analysis output

## Layer Schema (Navigator v4.5)

Output follows ATT&CK Navigator layer format v4.5:
- `domain`: "enterprise-attack" (default), "mobile-attack", or "ics-attack"
- `techniques[]`: Array of technique entries with color, score, and metadata
- `gradient`: Maps scores 0-100 to yellow→orange→red color range

## Color Coding by Confidence

| Confidence | Color | Hex | Score |
|-----------|-------|-----|-------|
| Confirmed/observed (high) | Red | #ff6666 | 85 |
| Likely/enrichment-based (medium) | Orange | #ffaa66 | 50 |
| Possible/low confidence (low) | Yellow | #ffff66 | 25 |

## Execution Protocol

```
THOUGHT: I have Diamond Model analysis with ATT&CK technique mappings. Generate a Navigator layer.

ACTION: Extract all ATT&CK technique IDs and their confidence levels from analysis output
OBSERVATION: Found N techniques across M tactics

ACTION: For each technique:
  1. Map confidence level to color and score
  2. Include tactic for positioning
  3. Add metadata (confidence level, evidence source)
  4. Add comment describing observation

ACTION: Build layer JSON with Navigator v4.5 schema
OBSERVATION: Layer contains N technique entries

ACTION: Save to reports/{guid}_attack_layer.json

CONCLUSION: ATT&CK Navigator layer generated with {N} techniques
```

## Integration Points

- **Capa-MCP**: Capa output maps directly to ATT&CK techniques — automatically feed results into layer
- **Diamond Model**: Kill chain phases provide tactic assignment
- **Enrichment data**: Source attribution provides confidence levels

## Output

- **File**: `reports/{guid}_attack_layer.json`
- **Format**: ATT&CK Navigator Layer JSON v4.5
- **Usage**: Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) or embed in reports
```

**Step 2: Verify SKILL.md has frontmatter**

Run: `head -3 skills/produce-attack-layers/SKILL.md`
Expected: Starts with `---`

**Step 3: Commit**

```bash
git add skills/produce-attack-layers/SKILL.md
git commit -m "feat: add produce-attack-layers skill"
```

---

### Task 7: External Skills Directory Structure

**Files:**
- Create: `skills/external/README.md`
- Create: `skills/external/.gitkeep`

**Step 1: Create external skills directory with README**

Create `skills/external/README.md`:

```markdown
# External Skills

Third-party skills integrated into CTI Agent. Each subdirectory contains skills
from an external source, installed per the project's skill conflict resolution
policy (see AGENT.md).

## Sources

| Directory | Source | Skills |
|-----------|--------|--------|
| `malware-analysis/` | [gl0bal01/malware-analysis-claude-skills](https://github.com/gl0bal01/malware-analysis-claude-skills) | 5 |
| `yara-rule-skill/` | [YARAHQ/yara-rule-skill](https://github.com/YARAHQ/yara-rule-skill) | 1 |
| `trailofbits/` | [trailofbits/skills](https://github.com/trailofbits/skills) | 6 |

## Conflict Resolution

- **YARA rules**: YARAHQ skill is primary author
- **Sigma rules**: gl0bal01's detection-engineer is primary author
- **Reports**: CTI Agent's generate-report orchestrates, delegates detection rules
```

**Step 2: Commit**

```bash
git add skills/external/
git commit -m "feat: add external skills directory structure"
```

---

### Task 8: Install gl0bal01 Malware Analysis Skills

**Files:**
- Create: `skills/external/malware-analysis/` (5 skill files)

**Step 1: Clone gl0bal01 skills into external directory**

```bash
cd /home/ryantreb/Security\ Projects/CTI_agent
git clone --depth 1 https://github.com/gl0bal01/malware-analysis-claude-skills.git /tmp/malware-analysis-skills
cp -r /tmp/malware-analysis-skills/.claude/skills/* skills/external/malware-analysis/ 2>/dev/null || \
cp -r /tmp/malware-analysis-skills/skills/* skills/external/malware-analysis/ 2>/dev/null || \
cp -r /tmp/malware-analysis-skills/*.md skills/external/malware-analysis/ 2>/dev/null
rm -rf /tmp/malware-analysis-skills
```

Note: The exact file layout depends on the repo structure. After cloning, verify that skill files are present. If the repo uses a different layout (e.g., `.claude/commands/` or root-level `.md` files), adjust the copy command accordingly.

**Step 2: Verify skills installed**

Run: `ls skills/external/malware-analysis/`
Expected: At least 5 skill files (malware-triage, malware-dynamic-analysis, specialized-file-analyzer, detection-engineer, malware-report-writer)

**Step 3: Commit**

```bash
git add skills/external/malware-analysis/
git commit -m "feat: integrate gl0bal01 malware analysis skills"
```

---

### Task 9: Install YARAHQ yara-rule-skill

**Files:**
- Create: `skills/external/yara-rule-skill/`

**Step 1: Clone YARAHQ skill**

```bash
cd /home/ryantreb/Security\ Projects/CTI_agent
git clone --depth 1 https://github.com/YARAHQ/yara-rule-skill.git /tmp/yara-rule-skill
cp -r /tmp/yara-rule-skill/.skill* skills/external/yara-rule-skill/ 2>/dev/null || \
cp -r /tmp/yara-rule-skill/skill* skills/external/yara-rule-skill/ 2>/dev/null || \
cp -r /tmp/yara-rule-skill/*.md skills/external/yara-rule-skill/ 2>/dev/null
rm -rf /tmp/yara-rule-skill
```

**Step 2: Verify skill installed**

Run: `ls skills/external/yara-rule-skill/`
Expected: Skill file(s) present

**Step 3: Commit**

```bash
git add skills/external/yara-rule-skill/
git commit -m "feat: integrate YARAHQ yara-rule-skill"
```

---

### Task 10: Install Trail of Bits Security Skills

**Files:**
- Create: `skills/external/trailofbits/` (6 selected skills)

**Step 1: Clone Trail of Bits skills (selected subset)**

```bash
cd /home/ryantreb/Security\ Projects/CTI_agent
git clone --depth 1 https://github.com/trailofbits/skills.git /tmp/tob-skills

# Copy selected skills
for skill in variant-analysis semgrep-rule-creator static-analysis differential-review insecure-defaults dwarf-expert; do
    if [ -d "/tmp/tob-skills/$skill" ]; then
        cp -r "/tmp/tob-skills/$skill" "skills/external/trailofbits/$skill"
    elif [ -d "/tmp/tob-skills/skills/$skill" ]; then
        cp -r "/tmp/tob-skills/skills/$skill" "skills/external/trailofbits/$skill"
    fi
done

rm -rf /tmp/tob-skills
```

**Step 2: Verify skills installed**

Run: `ls skills/external/trailofbits/`
Expected: 6 directories (variant-analysis, semgrep-rule-creator, static-analysis, differential-review, insecure-defaults, dwarf-expert)

**Step 3: Commit**

```bash
git add skills/external/trailofbits/
git commit -m "feat: integrate Trail of Bits security skills (6 selected)"
```

---

### Task 11: Skill Conflict Resolution Configuration

**Files:**
- Create: `config/skill_ownership.json`
- Modify: `skills/generate-report/SKILL.md`

**Step 1: Create skill ownership config**

Create `config/skill_ownership.json`:

```json
{
  "schema_version": "1.0",
  "ownership": {
    "yara_rules": {
      "primary": "external/yara-rule-skill",
      "description": "YARAHQ skill is the authoritative YARA rule author",
      "delegates_from": ["generate-report", "external/malware-analysis/detection-engineer"]
    },
    "sigma_rules": {
      "primary": "external/malware-analysis/detection-engineer",
      "description": "gl0bal01 detection-engineer is the authoritative Sigma rule author",
      "delegates_from": ["generate-report"]
    },
    "suricata_rules": {
      "primary": "external/malware-analysis/detection-engineer",
      "description": "gl0bal01 detection-engineer handles Suricata rules",
      "delegates_from": ["generate-report"]
    },
    "reports": {
      "primary": "generate-report",
      "description": "CTI Agent generate-report is the primary report skill",
      "alternatives": {
        "malware_deep_dive": "external/malware-analysis/malware-report-writer"
      }
    },
    "diamond_model": {
      "primary": "diamond-model-analysis",
      "description": "CTI Agent's own Diamond Model analysis. TI Mindmap HUB is source/validator only",
      "external_validators": ["ti-mindmap-hub-mcp"]
    }
  }
}
```

**Step 2: Update generate-report SKILL.md to reference delegation**

Add a "Detection Rule Delegation" section after the existing "Detection Artifacts" section in `skills/generate-report/SKILL.md`. The section should contain:

```markdown
## Detection Rule Delegation

When generating detection artifacts, delegate to specialized skills:

| Rule Type | Delegate To | Rationale |
|-----------|------------|-----------|
| YARA rules | `external/yara-rule-skill` | YARAHQ provides 20+ quality checks, naming conventions, performance optimization |
| Sigma rules | `external/malware-analysis/detection-engineer` | gl0bal01 provides IOC management and multi-format conversion |
| Suricata rules | `external/malware-analysis/detection-engineer` | Same skill handles network detection rules |

**Protocol**: Generate detection artifacts by invoking the specialized skill with the analysis context, rather than writing rules inline. This ensures professional quality and consistency.

See `config/skill_ownership.json` for the full ownership matrix.
```

**Step 3: Commit**

```bash
git add config/skill_ownership.json skills/generate-report/SKILL.md
git commit -m "feat: add skill conflict resolution configuration"
```

---

### Task 12: Demo Dataset

**Files:**
- Create: `demo/sample_input.json`
- Create: `demo/mock_mcp_responses/vt_response.json`
- Create: `demo/mock_mcp_responses/otx_response.json`
- Create: `demo/mock_mcp_responses/shodan_response.json`
- Create: `demo/expected_output/diamond_model.json`
- Create: `demo/expected_output/stix_bundle.json`
- Create: `demo/expected_output/attack_layer.json`
- Create: `demo/run_demo.sh`
- Create: `demo/README.md`

**Step 1: Create demo directory structure and sample input**

Create `demo/sample_input.json` — a synthetic threat report with IOCs:

```json
{
  "report_title": "APT29 Supply Chain Campaign - Demo",
  "report_date": "2026-02-16",
  "source": "CTI Agent Demo Dataset",
  "summary": "Synthetic threat report demonstrating CTI Agent pipeline. APT29 (Cozy Bear) conducts supply chain compromise via trojanized software update, establishing C2 via compromised infrastructure.",
  "iocs": [
    {"type": "ipv4-addr", "value": "198.51.100.42", "context": "C2 server"},
    {"type": "domain-name", "value": "update.example-malware.com", "context": "Payload delivery domain"},
    {"type": "sha-256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "context": "Trojanized installer hash"},
    {"type": "url", "value": "https://update.example-malware.com/patch.exe", "context": "Malicious download URL"}
  ],
  "ttps": [
    {"mitre_id": "T1195.002", "name": "Supply Chain Compromise: Compromise Software Supply Chain", "tactic": "initial-access", "confidence": "high"},
    {"mitre_id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution", "confidence": "high"},
    {"mitre_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control", "confidence": "medium"},
    {"mitre_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion", "confidence": "medium"}
  ],
  "attribution": {
    "actor": "APT29",
    "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
    "country": "Russia",
    "confidence": "likely"
  }
}
```

**Step 2: Create mock MCP responses**

Create `demo/mock_mcp_responses/vt_response.json`:

```json
{
  "server": "gti",
  "query": "198.51.100.42",
  "response": {
    "data": {
      "attributes": {
        "last_analysis_stats": {"malicious": 15, "suspicious": 3, "harmless": 50, "undetected": 12},
        "country": "RU",
        "as_owner": "Example Hosting",
        "reputation": -42,
        "tags": ["c2", "apt"]
      }
    }
  }
}
```

Create `demo/mock_mcp_responses/otx_response.json`:

```json
{
  "server": "otx-mcp",
  "query": "198.51.100.42",
  "response": {
    "pulse_count": 3,
    "pulses": [
      {"name": "APT29 Infrastructure 2026", "tags": ["apt29", "cozy-bear", "c2"]},
      {"name": "Russian Threat Actors", "tags": ["russia", "svr"]}
    ],
    "reputation": -85
  }
}
```

Create `demo/mock_mcp_responses/shodan_response.json`:

```json
{
  "server": "mcp-shodan",
  "query": "198.51.100.42",
  "response": {
    "ip_str": "198.51.100.42",
    "ports": [443, 8443, 22],
    "hostnames": ["update.example-malware.com"],
    "org": "Example Hosting LLC",
    "os": "Linux",
    "country_code": "RU",
    "vulns": ["CVE-2024-0001"]
  }
}
```

**Step 3: Create expected output files**

Create `demo/expected_output/diamond_model.json`:

```json
{
  "adversary": {
    "name": "APT29",
    "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
    "description": "Russian SVR-affiliated threat actor conducting supply chain attacks",
    "sophistication": "expert"
  },
  "infrastructure": {
    "name": "APT29 C2 Infrastructure",
    "types": ["command-and-control"],
    "iocs": [
      {"type": "ipv4-addr", "value": "198.51.100.42"},
      {"type": "domain-name", "value": "update.example-malware.com"},
      {"type": "sha-256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"type": "url", "value": "https://update.example-malware.com/patch.exe"}
    ]
  },
  "capability": {
    "malware": {
      "name": "Trojanized Installer",
      "types": ["backdoor", "trojan"],
      "is_family": false
    },
    "attack_patterns": [
      {"name": "Supply Chain Compromise", "mitre_id": "T1195.002", "kill_chain_phase": "initial-access", "confidence": "high"},
      {"name": "PowerShell", "mitre_id": "T1059.001", "kill_chain_phase": "execution", "confidence": "high"},
      {"name": "Web Protocols", "mitre_id": "T1071.001", "kill_chain_phase": "command-and-control", "confidence": "medium"},
      {"name": "Obfuscated Files", "mitre_id": "T1027", "kill_chain_phase": "defense-evasion", "confidence": "medium"}
    ]
  },
  "victim": {
    "name": "Target Organization",
    "identity_class": "organization",
    "sectors": ["technology"]
  }
}
```

Create `demo/expected_output/stix_bundle.json` — a valid STIX bundle (abbreviated, full version generated at runtime).

Create `demo/expected_output/attack_layer.json` — a valid ATT&CK Navigator layer with the 4 techniques.

**Step 4: Create run_demo.sh**

Create `demo/run_demo.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== CTI Agent Demo Mode ==="
echo "Using mock MCP responses (no API keys required)"
echo ""

export CTI_AGENT_DEMO_MODE=true

# Step 1: Generate STIX bundle from demo Diamond Model
echo "[1/3] Generating STIX 2.1 bundle from demo Diamond Model..."
uv run python -c "
import json
from lib.stix_builder import diamond_to_stix
with open('$SCRIPT_DIR/expected_output/diamond_model.json') as f:
    diamond = json.load(f)
bundle = diamond_to_stix(diamond)
output_path = '$SCRIPT_DIR/output/demo_stix_bundle.json'
import os; os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, 'w') as f:
    json.dump(bundle, f, indent=2)
print(f'  -> STIX bundle: {output_path} ({len(bundle[\"objects\"])} objects)')
"

# Step 2: Generate ATT&CK Navigator layer
echo "[2/3] Generating ATT&CK Navigator layer..."
uv run python -c "
import json
from lib.attack_layers import diamond_to_layer
with open('$SCRIPT_DIR/expected_output/diamond_model.json') as f:
    diamond = json.load(f)
layer = diamond_to_layer(diamond, report_guid='demo-001')
output_path = '$SCRIPT_DIR/output/demo_attack_layer.json'
with open(output_path, 'w') as f:
    json.dump(layer, f, indent=2)
print(f'  -> ATT&CK layer: {output_path} ({len(layer[\"techniques\"])} techniques)')
"

# Step 3: Run health check
echo "[3/3] Running health check..."
uv run python -c "
from lib.health_check import run_health_check
report = run_health_check()
print(f'  -> Servers: {report[\"total_servers\"]} total, {report[\"available_count\"]} available')
print(f'  -> Health: {report[\"health_percentage\"]:.0f}%')
"

echo ""
echo "=== Demo Complete ==="
echo "Output files in: $SCRIPT_DIR/output/"
```

**Step 5: Create demo README**

Create `demo/README.md`:

```markdown
# CTI Agent Demo Mode

Run the full CTI Agent pipeline with synthetic data and mock MCP responses.
No API keys required.

## Quick Start

```bash
chmod +x demo/run_demo.sh
./demo/run_demo.sh
```

## Contents

| File/Directory | Purpose |
|---------------|---------|
| `sample_input.json` | Synthetic APT29 threat report with IOCs and TTPs |
| `mock_mcp_responses/` | Cached MCP server responses for demo IOCs |
| `expected_output/` | Reference outputs at each pipeline stage |
| `run_demo.sh` | End-to-end pipeline runner |
| `output/` | Generated outputs (created by run_demo.sh) |
```

**Step 6: Commit**

```bash
git add demo/
git commit -m "feat: add demo dataset with mock MCP responses"
```

---

### Task 13: Update AGENT.md for v2.2.0

**Files:**
- Modify: `AGENT.md`

**Step 1: Update version to 2.2.0**

Change line 3: `**Version**: 2.1.0` → `**Version**: 2.2.0`
Change line 296: `v2.1.0` → `v2.2.0`

**Step 2: Add new skills to skill registry table**

Add after the `self-evolving-loop` row in the skill registry:

```markdown
| `produce-stix-bundle` | Transform Diamond Model output into STIX 2.1 bundles | 7.1 | diamond-model |
| `produce-attack-layers` | Generate ATT&CK Navigator layer JSON from analysis | 7.2 | diamond-model |
```

**Step 3: Add External Skills section**

Add a new section after the Skill Registry:

```markdown
### External Skills

| Source | Skills | Integration Point |
|--------|--------|-------------------|
| gl0bal01/malware-analysis | malware-triage, malware-dynamic-analysis, specialized-file-analyzer, detection-engineer, malware-report-writer | Malware analysis pipeline |
| YARAHQ/yara-rule-skill | yara-rule-skill | YARA detection rule authoring (primary) |
| trailofbits/skills | variant-analysis, semgrep-rule-creator, static-analysis, differential-review, insecure-defaults, dwarf-expert | Security analysis and detection engineering |

**Skill Conflict Resolution**: See `config/skill_ownership.json`. YARA → YARAHQ, Sigma → gl0bal01, Reports → CTI Agent's generate-report.
```

**Step 4: Add output types for STIX and ATT&CK layers**

Add to the Output Locations table:

```markdown
| STIX Bundles | `reports/{guid}_stix_bundle.json` | STIX 2.1 JSON |
| ATT&CK Layers | `reports/{guid}_attack_layer.json` | Navigator v4.5 JSON |
```

**Step 5: Commit**

```bash
git add AGENT.md
git commit -m "feat: update AGENT.md for v2.2.0 with new skills and external integrations"
```

---

### Task 14: Phase 2 Integration Tests

**Files:**
- Modify: `tests/test_integration.py`

**Step 1: Add Phase 2 integration tests**

Add to `tests/test_integration.py`:

```python
class TestSTIXBuilder:
    """STIX builder produces valid bundles from Diamond Model input."""

    def test_diamond_to_stix_produces_bundle(self):
        from lib.stix_builder import diamond_to_stix

        diamond = {
            "adversary": {"name": "TestActor"},
            "capability": {
                "attack_patterns": [
                    {"name": "Phishing", "mitre_id": "T1566", "kill_chain_phase": "initial-access"}
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
                    {"name": "Phishing", "mitre_id": "T1566", "kill_chain_phase": "initial-access", "confidence": "high"}
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
                    {"name": "Test", "mitre_id": "T1059", "kill_chain_phase": "execution", "confidence": "medium"}
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
            assert rule_type in ownership["ownership"], f"Missing ownership for {rule_type}"
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
```

**Step 2: Update version test**

Change the version assertion in `TestVersionTracking`:

```python
def test_agent_md_version_is_2_2_0(self):
    agent_md = (PROJECT_ROOT / "AGENT.md").read_text()
    assert "**Version**: 2.2.0" in agent_md
```

**Step 3: Run all tests**

Run: `uv run pytest tests/ -q`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add Phase 2 integration tests"
```

---

### Task 15: Tag v2.2.0

**Files:** None (git operation only)

**Step 1: Run full test suite**

Run: `uv run pytest tests/ -q`
Expected: All tests PASS

**Step 2: Run ruff checks**

Run: `ruff check lib/ tests/ --fix && ruff format lib/ tests/`
Expected: Clean

**Step 3: Tag release**

```bash
git tag -a v2.2.0 -m "CTI Agent v2.2.0: STIX 2.1 output, ATT&CK layers, external skills integration"
```

**Step 4: Verify tag**

Run: `git tag -l 'v2.*'`
Expected: Shows v2.1.0 and v2.2.0

---

*Plan complete. 15 tasks covering STIX 2.1 output, ATT&CK Navigator layers, external skills integration, skill conflict resolution, demo dataset, and documentation updates.*

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
            objects.append(
                create_relationship(
                    indicator["id"],
                    infra_obj["id"],
                    "indicates",
                )
            )

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
                external_references=[
                    {
                        "source_name": "mitre-attack",
                        "external_id": ap_info["mitre_id"],
                    }
                ],
                kill_chain_phases=[
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": ap_info.get("kill_chain_phase", ""),
                    }
                ],
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
        objects.append(
            create_relationship(refs["adversary"], refs["infrastructure"], "uses")
        )
    if "adversary" in refs and "victim" in refs:
        objects.append(
            create_relationship(refs["adversary"], refs["victim"], "targets")
        )
    if "malware" in refs and "victim" in refs:
        objects.append(create_relationship(refs["malware"], refs["victim"], "targets"))

    return build_stix_bundle(objects)

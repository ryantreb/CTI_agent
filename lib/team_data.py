"""Inter-agent data schemas for JTIA multi-agent team.

Defines typed data structures for handoffs between agents:
Collector → Analyst → Devil's Advocate → Verifier → Reporter.
"""

from datetime import datetime, timezone


def create_enriched_ioc(
    ioc_type: str,
    value: str,
    confidence: float,
    sources: list[str],
    *,
    ttps: list[str] | None = None,
    threat_actors: list[str] | None = None,
    verification_status: str = "UNVERIFIED",
    enrichment_data: dict | None = None,
) -> dict:
    """Create a structured enriched IOC for inter-agent passing."""
    return {
        "ioc_type": ioc_type,
        "value": value,
        "confidence": confidence,
        "sources": sources,
        "ttps": ttps or [],
        "threat_actors": threat_actors or [],
        "verification_status": verification_status,
        "enrichment_data": enrichment_data or {},
    }


def create_collection_bundle(
    session_id: str,
    sources_queried: list[str],
    *,
    enriched_iocs: list[dict] | None = None,
    raw_items: list[dict] | None = None,
    sources_unavailable: list[str] | None = None,
) -> dict:
    """Create a collection bundle for Collector → Analyst handoff."""
    return {
        "type": "collection_bundle",
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sources_queried": sources_queried,
        "sources_unavailable": sources_unavailable or [],
        "enriched_iocs": enriched_iocs or [],
        "raw_items": raw_items or [],
        "ioc_count": len(enriched_iocs or []),
        "item_count": len(raw_items or []),
    }


def create_key_judgment(
    judgment_id: str,
    statement: str,
    confidence: str,
    confidence_numeric: float,
    *,
    supporting_evidence: list[str] | None = None,
    contradicting_evidence: list[str] | None = None,
    assumptions: list[str] | None = None,
) -> dict:
    """Create a structured key judgment for assessment packages."""
    return {
        "judgment_id": judgment_id,
        "statement": statement,
        "confidence": confidence,
        "confidence_numeric": confidence_numeric,
        "supporting_evidence": supporting_evidence or [],
        "contradicting_evidence": contradicting_evidence or [],
        "assumptions": assumptions or [],
    }


def create_assessment_package(
    session_id: str,
    diamond_model: dict,
    ach_result: dict,
    key_judgments: list[dict],
    *,
    ttps_identified: list[str] | None = None,
    actor_profiles_referenced: list[str] | None = None,
    intelligence_gaps: list[str] | None = None,
) -> dict:
    """Create an assessment package for Analyst → Devil's Advocate handoff."""
    return {
        "type": "assessment_package",
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "diamond_model": diamond_model,
        "ach_result": ach_result,
        "key_judgments": key_judgments,
        "ttps_identified": ttps_identified or [],
        "actor_profiles_referenced": actor_profiles_referenced or [],
        "intelligence_gaps": intelligence_gaps or [],
    }

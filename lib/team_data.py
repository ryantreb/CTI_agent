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

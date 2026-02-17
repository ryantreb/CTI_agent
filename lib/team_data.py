"""Inter-agent data schemas for CTI Agent multi-agent team.

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


def create_challenge(
    target_judgment_id: str,
    challenge_type: str,
    argument: str,
    counter_evidence: list[str],
    *,
    proposed_confidence_adjustment: float = 0.0,
    alternative_hypothesis: str | None = None,
) -> dict:
    """Create a Devil's Advocate challenge against a key judgment."""
    return {
        "target_judgment_id": target_judgment_id,
        "challenge_type": challenge_type,
        "argument": argument,
        "counter_evidence": counter_evidence,
        "proposed_confidence_adjustment": proposed_confidence_adjustment,
        "alternative_hypothesis": alternative_hypothesis,
    }


def create_debate_record(
    session_id: str,
    assessment_package: dict,
    challenges: list[dict],
    rounds_completed: int,
    consensus_reached: bool,
    *,
    analyst_responses: list[dict] | None = None,
    final_judgments: list[dict] | None = None,
    dissenting_views: list[str] | None = None,
) -> dict:
    """Create a debate record for Devil's Advocate / Analyst exchange."""
    return {
        "type": "debate_record",
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "assessment_package": assessment_package,
        "challenges": challenges,
        "rounds_completed": rounds_completed,
        "consensus_reached": consensus_reached,
        "analyst_responses": analyst_responses or [],
        "final_judgments": final_judgments or [],
        "dissenting_views": dissenting_views or [],
    }


def create_verified_claim(
    claim_id: str,
    original_claim: str,
    claim_type: str,
    verification_status: str,
    confidence_score: float,
    sources_checked: list[str],
    *,
    discrepancies: list[str] | None = None,
    api_responses: list[dict] | None = None,
) -> dict:
    """Create a verified claim entry for the verification report."""
    return {
        "claim_id": claim_id,
        "original_claim": original_claim,
        "claim_type": claim_type,
        "verification_status": verification_status,
        "confidence_score": confidence_score,
        "sources_checked": sources_checked,
        "discrepancies": discrepancies or [],
        "api_responses": api_responses or [],
    }


def create_verification_report(
    session_id: str,
    verified_claims: list[dict],
    refuted_claims: list[dict],
    unverified_claims: list[dict],
    *,
    hallucination_flags: list[str] | None = None,
) -> dict:
    """Create a verification report for Verifier / Reporter handoff."""
    return {
        "type": "verification_report",
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verified_claims": verified_claims,
        "refuted_claims": refuted_claims,
        "unverified_claims": unverified_claims,
        "total_claims": len(verified_claims)
        + len(refuted_claims)
        + len(unverified_claims),
        "verified_count": len(verified_claims),
        "refuted_count": len(refuted_claims),
        "unverified_count": len(unverified_claims),
        "hallucination_flags": hallucination_flags or [],
    }

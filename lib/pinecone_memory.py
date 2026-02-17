"""Pinecone vector memory integration for CTI Agent.

Provides record construction and query formatting for the Pinecone MCP server.
Actual Pinecone operations are performed via MCP tool calls in SKILL.md skills.
This library handles schema construction and result formatting.
"""

from datetime import datetime, timezone

PINECONE_INDEX = "jtia-intel-memory"


def build_intel_record(
    report_guid: str,
    summary: str,
    *,
    report_type: str = "",
    threat_actors: list[str] | None = None,
    ttps: list[str] | None = None,
    ioc_types: list[str] | None = None,
    confidence: float = 0.0,
    campaign: str = "",
) -> dict:
    """Build a Pinecone record from a CTI Agent intelligence report."""
    return {
        "_id": f"report-{report_guid}",
        "text": summary,
        "report_type": report_type,
        "threat_actors": threat_actors or [],
        "ttps": ttps or [],
        "ioc_types": ioc_types or [],
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "confidence": confidence,
        "campaign": campaign,
    }


def build_actor_record(profile: dict) -> dict:
    """Build a Pinecone record from a threat actor profile."""
    text_parts = [
        f"Threat Actor: {profile['actor_id']}",
        f"Aliases: {', '.join(profile.get('aliases', []))}",
        f"Motivation: {profile.get('motivation', 'unknown')}",
        f"Nation State: {profile.get('nation_state', 'unknown')}",
    ]
    ttps = [t["technique"] for t in profile.get("known_ttps", [])]
    if ttps:
        text_parts.append(f"TTPs: {', '.join(ttps)}")
    targeting = profile.get("targeting", {})
    if targeting.get("sectors"):
        text_parts.append(f"Targets: {', '.join(targeting['sectors'])}")

    return {
        "_id": f"actor-{profile['actor_id']}",
        "text": ". ".join(text_parts),
        "threat_actors": [profile["actor_id"]] + profile.get("aliases", []),
        "ttps": ttps,
        "date": profile.get("last_updated", ""),
    }


def build_search_query(
    query_text: str,
    *,
    top_k: int = 5,
    filter_by: dict | None = None,
) -> dict:
    """Build a Pinecone search query for the MCP server."""
    query = {
        "index": PINECONE_INDEX,
        "query": query_text,
        "top_k": top_k,
    }
    if filter_by:
        query["filter"] = filter_by
    return query


def format_search_results(raw_results: list[dict]) -> list[dict]:
    """Format Pinecone search results for use in analysis skills."""
    formatted = []
    for result in raw_results:
        formatted.append(
            {
                "id": result.get("_id", ""),
                "relevance_score": result.get("_score", 0.0),
                "text": result.get("text", ""),
                "report_type": result.get("report_type", ""),
                "date": result.get("date", ""),
            }
        )
    return formatted

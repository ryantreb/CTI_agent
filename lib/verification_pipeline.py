"""Verification pipeline for JTIA multi-agent team.

Extracts verifiable claims from assessment packages, routes them to
appropriate verification strategies, and detects hallucination patterns.
Used by the Verifier agent to independently validate all claims.
"""

import re

IOC_VERIFICATION_ROUTES: dict[str, list[str]] = {
    "ipv4-addr": ["gti", "mcp-shodan", "fastmcp-threatintel"],
    "domain-name": ["gti", "mcp-censys", "mcp-dnstwist"],
    "file": ["gti", "mcp-threatintel"],
    "url": ["gti", "mcp-threatintel"],
}

REFUTATION_RATE_THRESHOLD = 0.5


def extract_claims_from_assessment(assessment: dict) -> list[dict]:
    """Extract all verifiable claims from an assessment package."""
    claims = []
    claim_counter = 0

    diamond = assessment.get("diamond_model", {})
    infra = diamond.get("infrastructure", {})
    for ioc in infra.get("iocs", []):
        claim_counter += 1
        claims.append(
            {
                "claim_id": f"C{claim_counter}",
                "claim_type": "IOC",
                "ioc_type": ioc.get("type", "unknown"),
                "value": ioc.get("value", ""),
                "original_claim": f"IOC {ioc.get('value', '')} observed in infrastructure",
            }
        )

    for ttp in assessment.get("ttps_identified", []):
        claim_counter += 1
        claims.append(
            {
                "claim_id": f"C{claim_counter}",
                "claim_type": "TTP",
                "value": ttp,
                "original_claim": f"Technique {ttp} identified in attack",
            }
        )

    for judgment in assessment.get("key_judgments", []):
        statement = judgment.get("statement", "")
        attribution_pattern = re.compile(
            r"(APT\d+|FIN\d+|Lazarus|Cozy Bear|Fancy Bear|\w+\s+Group)",
            re.IGNORECASE,
        )
        match = attribution_pattern.search(statement)
        if match:
            claim_counter += 1
            claims.append(
                {
                    "claim_id": f"C{claim_counter}",
                    "claim_type": "ATTRIBUTION",
                    "actor": match.group(0),
                    "value": match.group(0),
                    "original_claim": statement,
                }
            )

    adversary = diamond.get("adversary", {})
    if adversary.get("name"):
        claim_counter += 1
        claims.append(
            {
                "claim_id": f"C{claim_counter}",
                "claim_type": "ATTRIBUTION",
                "actor": adversary["name"],
                "value": adversary["name"],
                "original_claim": f"Activity attributed to {adversary['name']}",
            }
        )

    return claims


def classify_claim_for_verification(claim: dict) -> dict:
    """Route a claim to the appropriate verification strategy and servers."""
    claim_type = claim.get("claim_type", "")

    if claim_type == "IOC":
        ioc_type = claim.get("ioc_type", "unknown")
        servers = IOC_VERIFICATION_ROUTES.get(ioc_type, ["gti"])
        return {"strategy": "mcp_verification", "servers": servers}

    if claim_type == "TTP":
        return {"strategy": "attack_lookup", "servers": []}

    if claim_type == "ATTRIBUTION":
        return {
            "strategy": "multi_source_verification",
            "servers": ["gti", "otx-mcp", "mcp-security-orkl", "mallory-mcp-server"],
        }

    return {"strategy": "manual_review", "servers": []}


def aggregate_verification_results(results: list[dict]) -> dict:
    """Aggregate individual verification results into summary statistics."""
    total = len(results)
    if total == 0:
        return {
            "total": 0,
            "verified_high": 0,
            "verified_medium": 0,
            "verified_low": 0,
            "unverified": 0,
            "refuted": 0,
            "pass_rate": 0.0,
        }

    counts: dict[str, int] = {
        "verified_high": 0,
        "verified_medium": 0,
        "verified_low": 0,
        "unverified": 0,
        "refuted": 0,
    }
    for r in results:
        status = r.get("verification_status", "UNVERIFIED").lower().replace(" ", "_")
        if status in counts:
            counts[status] += 1

    passed = (
        counts["verified_high"] + counts["verified_medium"] + counts["verified_low"]
    )
    return {
        "total": total,
        **counts,
        "pass_rate": passed / total,
    }


def detect_hallucination_patterns(claims: list[dict]) -> list[str]:
    """Detect patterns suggesting fabricated or hallucinated claims."""
    flags = []

    for claim in claims:
        if not claim.get("sources_checked"):
            flags.append(
                f"{claim['claim_id']}: No sources checked — possible fabrication"
            )

    if claims:
        refuted = sum(1 for c in claims if c.get("verification_status") == "REFUTED")
        rate = refuted / len(claims)
        if rate >= REFUTATION_RATE_THRESHOLD:
            flags.append(
                f"High refutation rate ({rate:.0%}) across {len(claims)} claims — "
                f"possible systematic hallucination"
            )

    return flags

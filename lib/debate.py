"""Devil's Advocate debate engine for CTI Agent multi-agent team.

Implements structured adversarial debate per ICD 203 Alternative Analysis
requirements. The Devil's Advocate MUST challenge any assessment rated
'highly likely' or above.
"""

MAX_DEBATE_ROUNDS = 3

MANDATORY_CHALLENGE_THRESHOLDS = {"highly likely", "almost certain"}

CHALLENGE_TYPES = {
    "alternative_hypothesis",
    "evidence_underweighted",
    "source_reliability",
    "deception_hypothesis",
    "assumption_challenge",
}


def should_challenge(judgment: dict) -> bool:
    """Determine if a judgment requires mandatory Devil's Advocate challenge."""
    return judgment.get("confidence", "").lower() in MANDATORY_CHALLENGE_THRESHOLDS


def generate_challenge_types(judgment: dict) -> list[str]:
    """Generate appropriate challenge types for a given judgment."""
    types = []
    statement = judgment.get("statement", "").lower()
    contradicting = judgment.get("contradicting_evidence", [])
    supporting = judgment.get("supporting_evidence", [])

    attribution_keywords = {
        "responsible",
        "attributed",
        "conducted",
        "actor",
        "apt",
        "group",
    }
    if any(kw in statement for kw in attribution_keywords):
        types.append("alternative_hypothesis")

    if contradicting:
        types.append("evidence_underweighted")

    if len(supporting) <= 1:
        types.append("source_reliability")

    if not types:
        types.append("alternative_hypothesis")

    return types


def check_consensus(
    challenges: list[dict],
    analyst_responses: list[dict],
    round_num: int,
) -> dict:
    """Determine if debate has reached consensus or deadlock."""
    if not challenges:
        return {"consensus": True, "reason": "no_challenges", "document_dissent": False}

    if round_num >= MAX_DEBATE_ROUNDS:
        return {
            "consensus": False,
            "reason": "max_rounds_reached",
            "document_dissent": True,
        }

    all_accepted = all(r.get("accepted", False) for r in analyst_responses)
    if all_accepted:
        return {"consensus": True, "reason": "all_accepted", "document_dissent": False}

    return {
        "consensus": False,
        "reason": "unresolved_challenges",
        "document_dissent": False,
    }


def build_alternative_analysis_section(debate_record: dict) -> str:
    """Build the Alternative Analysis section for ICD 203 report compliance."""
    challenges = debate_record.get("challenges", [])
    responses = debate_record.get("analyst_responses", [])
    dissenting = debate_record.get("dissenting_views", [])
    consensus = debate_record.get("consensus_reached", True)

    if not challenges:
        return (
            "## Alternative Analysis\n\n"
            "No significant challenges were raised during adversarial review. "
            "All key judgments were assessed without dissent."
        )

    lines = ["## Alternative Analysis\n"]
    lines.append(
        "The following alternative interpretations were considered "
        "during structured adversarial review:\n"
    )

    for i, challenge in enumerate(challenges):
        target = challenge.get("target_judgment_id", f"KJ{i + 1}")
        argument = challenge.get("argument", "")
        counter = challenge.get("counter_evidence", [])

        lines.append(f"### Challenge to {target}\n")
        lines.append(f"**Argument:** {argument}\n")
        if counter:
            lines.append("**Counter-evidence:**")
            for c in counter:
                lines.append(f"- {c}")
            lines.append("")

        matching_response = next(
            (r for r in responses if r.get("challenge_id") == i), None
        )
        if matching_response:
            accepted = matching_response.get("accepted", False)
            rebuttal = matching_response.get("rebuttal", "")
            status = "Accepted" if accepted else "Rejected"
            lines.append(f"**Analyst response:** {status} — {rebuttal}\n")

    if dissenting:
        lines.append("### Dissenting Views\n")
        for view in dissenting:
            lines.append(f"- {view}")
        lines.append("")

    if not consensus:
        lines.append(
            "*Note: Consensus was not reached on all points. "
            "Dissenting views are documented above per ICD 203 requirements.*"
        )

    return "\n".join(lines)

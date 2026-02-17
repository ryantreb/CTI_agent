# CTI Agent v2.4.0 Phase 4: Multi-Agent Teams Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a 5-agent intelligence team (Collector, Analyst, Devil's Advocate, Verifier, Reporter) with structured inter-agent data passing, adversarial debate protocol, and independent claim verification.

**Architecture:** Agent roles are defined as markdown instruction files in `agents/definitions/`. Inter-agent data flows through typed Python data structures in `lib/team_data.py`. A team orchestration skill (`skills/orchestrate-team/SKILL.md`) sequences the pipeline: Collector → Analyst → Devil's Advocate ↔ Analyst debate → Verifier → Reporter. Debate and verification logic live in `lib/debate.py` and `lib/verification_pipeline.py`.

**Tech Stack:** Python 3.12+, pytest, ruff, JSON schemas, SKILL.md prompt orchestration

---

## Task 1: Inter-Agent Data Schemas — Collection Bundle

**Files:**
- Create: `tests/test_team_data.py`
- Create: `lib/team_data.py`

**Step 1: Write the failing tests for collection bundle**

```python
"""Tests for inter-agent data schemas."""

import pytest
from lib.team_data import (
    create_collection_bundle,
    create_enriched_ioc,
)


class TestCollectionBundle:
    """Collection bundle data structure for Collector → Analyst handoff."""

    def test_create_collection_bundle_minimal(self):
        bundle = create_collection_bundle(
            session_id="test-session",
            sources_queried=["feedly", "otx"],
        )
        assert bundle["session_id"] == "test-session"
        assert bundle["sources_queried"] == ["feedly", "otx"]
        assert bundle["enriched_iocs"] == []
        assert bundle["raw_items"] == []
        assert "timestamp" in bundle

    def test_create_collection_bundle_with_iocs(self):
        ioc = create_enriched_ioc(
            ioc_type="ip",
            value="10.0.0.1",
            confidence=0.85,
            sources=["gti", "shodan"],
        )
        bundle = create_collection_bundle(
            session_id="test-session",
            sources_queried=["feedly"],
            enriched_iocs=[ioc],
        )
        assert len(bundle["enriched_iocs"]) == 1
        assert bundle["enriched_iocs"][0]["value"] == "10.0.0.1"

    def test_create_enriched_ioc(self):
        ioc = create_enriched_ioc(
            ioc_type="hash",
            value="abc123",
            confidence=0.9,
            sources=["gti"],
            ttps=["T1566.001"],
            verification_status="VERIFIED_HIGH",
        )
        assert ioc["ioc_type"] == "hash"
        assert ioc["confidence"] == 0.9
        assert ioc["ttps"] == ["T1566.001"]
        assert ioc["verification_status"] == "VERIFIED_HIGH"

    def test_create_enriched_ioc_defaults(self):
        ioc = create_enriched_ioc(
            ioc_type="domain",
            value="evil.com",
            confidence=0.5,
            sources=["gti"],
        )
        assert ioc["ttps"] == []
        assert ioc["verification_status"] == "UNVERIFIED"
        assert ioc["threat_actors"] == []
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_team_data.py::TestCollectionBundle -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.team_data'`

**Step 3: Write minimal implementation**

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_team_data.py::TestCollectionBundle -q`
Expected: 4 passed

**Step 5: Commit**

```bash
git add tests/test_team_data.py lib/team_data.py
git commit -m "feat: add collection bundle schema for Collector agent"
```

---

## Task 2: Inter-Agent Data Schemas — Assessment Package

**Files:**
- Modify: `tests/test_team_data.py`
- Modify: `lib/team_data.py`

**Step 1: Write the failing tests for assessment package**

Add to `tests/test_team_data.py`:

```python
from lib.team_data import create_assessment_package, create_key_judgment


class TestAssessmentPackage:
    """Assessment package for Analyst → Devil's Advocate handoff."""

    def test_create_key_judgment(self):
        judgment = create_key_judgment(
            judgment_id="KJ1",
            statement="APT29 is likely responsible",
            confidence="likely",
            confidence_numeric=0.70,
            supporting_evidence=["Known malware signature", "Targeting pattern"],
            assumptions=["Attribution data is accurate"],
        )
        assert judgment["judgment_id"] == "KJ1"
        assert judgment["confidence"] == "likely"
        assert len(judgment["supporting_evidence"]) == 2

    def test_create_assessment_package(self):
        judgment = create_key_judgment(
            judgment_id="KJ1",
            statement="Test assessment",
            confidence="likely",
            confidence_numeric=0.70,
        )
        package = create_assessment_package(
            session_id="test-session",
            diamond_model={"adversary": {"name": "APT29"}},
            ach_result={"most_likely": "H1"},
            key_judgments=[judgment],
        )
        assert package["type"] == "assessment_package"
        assert package["diamond_model"]["adversary"]["name"] == "APT29"
        assert len(package["key_judgments"]) == 1

    def test_assessment_package_includes_evidence_matrix(self):
        package = create_assessment_package(
            session_id="test-session",
            diamond_model={},
            ach_result={"evidence_matrix": [{"evidence": "E1"}]},
            key_judgments=[],
            ttps_identified=["T1566.001", "T1059.001"],
        )
        assert package["ttps_identified"] == ["T1566.001", "T1059.001"]
        assert package["ach_result"]["evidence_matrix"][0]["evidence"] == "E1"
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_team_data.py::TestAssessmentPackage -q`
Expected: FAIL — `ImportError: cannot import name 'create_assessment_package'`

**Step 3: Write minimal implementation**

Add to `lib/team_data.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_team_data.py::TestAssessmentPackage -q`
Expected: 3 passed

**Step 5: Commit**

```bash
git add tests/test_team_data.py lib/team_data.py
git commit -m "feat: add assessment package schema for Analyst agent"
```

---

## Task 3: Inter-Agent Data Schemas — Debate Record & Verification Report

**Files:**
- Modify: `tests/test_team_data.py`
- Modify: `lib/team_data.py`

**Step 1: Write the failing tests**

Add to `tests/test_team_data.py`:

```python
from lib.team_data import (
    create_debate_record,
    create_challenge,
    create_verification_report,
    create_verified_claim,
)


class TestDebateRecord:
    """Debate record for Devil's Advocate ↔ Analyst exchange."""

    def test_create_challenge(self):
        challenge = create_challenge(
            target_judgment_id="KJ1",
            challenge_type="alternative_hypothesis",
            argument="Criminal group mimicking APT29 TTPs is equally plausible",
            counter_evidence=["No financial motive found", "Tool reuse is common"],
            proposed_confidence_adjustment=-0.15,
        )
        assert challenge["target_judgment_id"] == "KJ1"
        assert challenge["challenge_type"] == "alternative_hypothesis"
        assert challenge["proposed_confidence_adjustment"] == -0.15

    def test_create_debate_record(self):
        challenge = create_challenge(
            target_judgment_id="KJ1",
            challenge_type="evidence_underweighted",
            argument="Absence of financial exfiltration undermines espionage hypothesis",
            counter_evidence=["No data exfil observed"],
        )
        record = create_debate_record(
            session_id="test-session",
            assessment_package={"type": "assessment_package"},
            challenges=[challenge],
            rounds_completed=1,
            consensus_reached=False,
        )
        assert record["type"] == "debate_record"
        assert record["rounds_completed"] == 1
        assert record["consensus_reached"] is False
        assert len(record["challenges"]) == 1

    def test_debate_record_with_analyst_responses(self):
        record = create_debate_record(
            session_id="test-session",
            assessment_package={},
            challenges=[],
            rounds_completed=2,
            consensus_reached=True,
            analyst_responses=[
                {"challenge_id": 0, "response": "Accepted", "adjustment": "Reduced to 'roughly even chance'"}
            ],
            final_judgments=[
                {"judgment_id": "KJ1", "revised_confidence": "roughly even chance"}
            ],
        )
        assert record["consensus_reached"] is True
        assert len(record["analyst_responses"]) == 1
        assert len(record["final_judgments"]) == 1


class TestVerificationReport:
    """Verification report for Verifier → Reporter handoff."""

    def test_create_verified_claim(self):
        claim = create_verified_claim(
            claim_id="C1",
            original_claim="Hash abc123 has 45 detections",
            claim_type="IOC",
            verification_status="VERIFIED_HIGH",
            confidence_score=0.95,
            sources_checked=["gti", "mcp-threatintel"],
        )
        assert claim["verification_status"] == "VERIFIED_HIGH"
        assert claim["confidence_score"] == 0.95

    def test_create_verification_report(self):
        claim = create_verified_claim(
            claim_id="C1",
            original_claim="Test claim",
            claim_type="IOC",
            verification_status="VERIFIED_HIGH",
            confidence_score=0.95,
            sources_checked=["gti"],
        )
        report = create_verification_report(
            session_id="test-session",
            verified_claims=[claim],
            refuted_claims=[],
            unverified_claims=[],
        )
        assert report["type"] == "verification_report"
        assert report["total_claims"] == 1
        assert report["verified_count"] == 1
        assert report["refuted_count"] == 0
        assert report["hallucination_flags"] == []

    def test_verification_report_with_hallucinations(self):
        refuted = create_verified_claim(
            claim_id="C2",
            original_claim="IP 1.2.3.4 is a known C2",
            claim_type="IOC",
            verification_status="REFUTED",
            confidence_score=0.0,
            sources_checked=["gti", "shodan"],
            discrepancies=["IP not found in any threat database"],
        )
        report = create_verification_report(
            session_id="test-session",
            verified_claims=[],
            refuted_claims=[refuted],
            unverified_claims=[],
            hallucination_flags=["C2: IP claimed as C2 but not found in any source"],
        )
        assert report["refuted_count"] == 1
        assert len(report["hallucination_flags"]) == 1
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_team_data.py::TestDebateRecord tests/test_team_data.py::TestVerificationReport -q`
Expected: FAIL — `ImportError`

**Step 3: Write minimal implementation**

Add to `lib/team_data.py`:

```python
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
    """Create a debate record for Devil's Advocate ↔ Analyst exchange."""
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
    """Create a verification report for Verifier → Reporter handoff."""
    return {
        "type": "verification_report",
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verified_claims": verified_claims,
        "refuted_claims": refuted_claims,
        "unverified_claims": unverified_claims,
        "total_claims": len(verified_claims) + len(refuted_claims) + len(unverified_claims),
        "verified_count": len(verified_claims),
        "refuted_count": len(refuted_claims),
        "unverified_count": len(unverified_claims),
        "hallucination_flags": hallucination_flags or [],
    }
```

**Step 4: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_team_data.py -q`
Expected: 11 passed

**Step 5: Commit**

```bash
git add tests/test_team_data.py lib/team_data.py
git commit -m "feat: add debate record and verification report schemas"
```

---

## Task 4: Debate Engine Library

**Files:**
- Create: `tests/test_debate.py`
- Create: `lib/debate.py`

**Step 1: Write the failing tests**

```python
"""Tests for Devil's Advocate debate engine."""

import pytest
from lib.debate import (
    should_challenge,
    generate_challenge_types,
    check_consensus,
    build_alternative_analysis_section,
    MAX_DEBATE_ROUNDS,
)


class TestShouldChallenge:
    """Determine which judgments require Devil's Advocate challenge."""

    def test_highly_likely_requires_challenge(self):
        judgment = {"confidence": "highly likely", "confidence_numeric": 0.85}
        assert should_challenge(judgment) is True

    def test_almost_certain_requires_challenge(self):
        judgment = {"confidence": "almost certain", "confidence_numeric": 0.97}
        assert should_challenge(judgment) is True

    def test_likely_does_not_require_mandatory_challenge(self):
        judgment = {"confidence": "likely", "confidence_numeric": 0.70}
        assert should_challenge(judgment) is False

    def test_roughly_even_does_not_require_challenge(self):
        judgment = {"confidence": "roughly even chance", "confidence_numeric": 0.50}
        assert should_challenge(judgment) is False


class TestGenerateChallengeTypes:
    """Generate appropriate challenge types for a judgment."""

    def test_attribution_judgment_gets_alternative_hypothesis(self):
        judgment = {
            "statement": "APT29 is highly likely responsible",
            "confidence": "highly likely",
            "supporting_evidence": ["malware match", "targeting pattern"],
        }
        types = generate_challenge_types(judgment)
        assert "alternative_hypothesis" in types

    def test_high_confidence_gets_evidence_underweighted(self):
        judgment = {
            "statement": "The attack used supply chain compromise",
            "confidence": "highly likely",
            "contradicting_evidence": ["No access to supply chain confirmed"],
        }
        types = generate_challenge_types(judgment)
        assert "evidence_underweighted" in types

    def test_single_source_gets_source_reliability(self):
        judgment = {
            "statement": "Actor is state-sponsored",
            "confidence": "highly likely",
            "supporting_evidence": ["single vendor report"],
        }
        types = generate_challenge_types(judgment)
        assert "source_reliability" in types


class TestCheckConsensus:
    """Determine if debate has reached consensus or deadlock."""

    def test_no_challenges_is_consensus(self):
        result = check_consensus(challenges=[], analyst_responses=[], round_num=1)
        assert result["consensus"] is True
        assert result["reason"] == "no_challenges"

    def test_all_accepted_is_consensus(self):
        responses = [
            {"challenge_id": 0, "accepted": True},
            {"challenge_id": 1, "accepted": True},
        ]
        result = check_consensus(
            challenges=[{}, {}],
            analyst_responses=responses,
            round_num=1,
        )
        assert result["consensus"] is True

    def test_disagreement_continues_debate(self):
        responses = [
            {"challenge_id": 0, "accepted": False, "rebuttal": "Evidence is strong"},
        ]
        result = check_consensus(
            challenges=[{}],
            analyst_responses=responses,
            round_num=1,
        )
        assert result["consensus"] is False
        assert result["reason"] == "unresolved_challenges"

    def test_max_rounds_forces_deadlock(self):
        responses = [
            {"challenge_id": 0, "accepted": False, "rebuttal": "Disagree"},
        ]
        result = check_consensus(
            challenges=[{}],
            analyst_responses=responses,
            round_num=MAX_DEBATE_ROUNDS,
        )
        assert result["consensus"] is False
        assert result["reason"] == "max_rounds_reached"
        assert result["document_dissent"] is True


class TestBuildAlternativeAnalysisSection:
    """Build the Alternative Analysis section for ICD 203 compliance."""

    def test_builds_section_from_debate_record(self):
        debate_record = {
            "challenges": [
                {
                    "target_judgment_id": "KJ1",
                    "argument": "Criminal mimicry is equally plausible",
                    "counter_evidence": ["Tool reuse is common"],
                }
            ],
            "analyst_responses": [
                {"challenge_id": 0, "accepted": False, "rebuttal": "Tooling is custom"}
            ],
            "consensus_reached": False,
            "dissenting_views": ["Criminal mimicry cannot be ruled out"],
        }
        section = build_alternative_analysis_section(debate_record)
        assert "Alternative Analysis" in section
        assert "Criminal mimicry" in section
        assert "dissent" in section.lower() or "Dissenting" in section

    def test_empty_debate_returns_minimal_section(self):
        debate_record = {
            "challenges": [],
            "analyst_responses": [],
            "consensus_reached": True,
            "dissenting_views": [],
        }
        section = build_alternative_analysis_section(debate_record)
        assert "Alternative Analysis" in section
        assert "no significant challenges" in section.lower()
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_debate.py -q`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

```python
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

    # Attribution claims always get alternative hypothesis challenge
    attribution_keywords = {"responsible", "attributed", "conducted", "actor", "apt", "group"}
    if any(kw in statement for kw in attribution_keywords):
        types.append("alternative_hypothesis")

    # If contradicting evidence exists, it may be underweighted
    if contradicting:
        types.append("evidence_underweighted")

    # Single-source evidence gets reliability challenge
    if len(supporting) <= 1:
        types.append("source_reliability")

    # Always include at least alternative_hypothesis for high confidence
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

        # Include analyst response if available
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_debate.py -q`
Expected: 10 passed

**Step 5: Lint and commit**

```bash
cd "/home/ryantreb/Security Projects/CTI_agent" && ruff check lib/debate.py tests/test_debate.py --fix && ruff format lib/debate.py tests/test_debate.py
git add tests/test_debate.py lib/debate.py
git commit -m "feat: add Devil's Advocate debate engine with consensus detection"
```

---

## Task 5: Verification Pipeline Library

**Files:**
- Create: `tests/test_verification_pipeline.py`
- Create: `lib/verification_pipeline.py`

**Step 1: Write the failing tests**

```python
"""Tests for verification pipeline."""

import pytest
from lib.verification_pipeline import (
    extract_claims_from_assessment,
    classify_claim_for_verification,
    aggregate_verification_results,
    detect_hallucination_patterns,
)


class TestExtractClaims:
    """Extract verifiable claims from assessment packages."""

    def test_extracts_ioc_claims(self):
        assessment = {
            "diamond_model": {
                "infrastructure": {
                    "iocs": [
                        {"type": "ipv4-addr", "value": "10.0.0.1"},
                        {"type": "domain-name", "value": "evil.com"},
                    ]
                }
            },
            "key_judgments": [],
        }
        claims = extract_claims_from_assessment(assessment)
        ioc_claims = [c for c in claims if c["claim_type"] == "IOC"]
        assert len(ioc_claims) == 2

    def test_extracts_ttp_claims(self):
        assessment = {
            "diamond_model": {},
            "ttps_identified": ["T1566.001", "T1059.001"],
            "key_judgments": [],
        }
        claims = extract_claims_from_assessment(assessment)
        ttp_claims = [c for c in claims if c["claim_type"] == "TTP"]
        assert len(ttp_claims) == 2

    def test_extracts_attribution_claims(self):
        assessment = {
            "diamond_model": {"adversary": {"name": "APT29"}},
            "key_judgments": [
                {
                    "judgment_id": "KJ1",
                    "statement": "APT29 is likely responsible",
                    "confidence": "likely",
                }
            ],
        }
        claims = extract_claims_from_assessment(assessment)
        attr_claims = [c for c in claims if c["claim_type"] == "ATTRIBUTION"]
        assert len(attr_claims) >= 1


class TestClassifyClaim:
    """Route claims to appropriate verification strategy."""

    def test_ioc_claim_routes_to_mcp(self):
        claim = {"claim_type": "IOC", "value": "10.0.0.1", "ioc_type": "ipv4-addr"}
        result = classify_claim_for_verification(claim)
        assert result["strategy"] == "mcp_verification"
        assert "gti" in result["servers"]

    def test_ttp_claim_routes_to_attack_lookup(self):
        claim = {"claim_type": "TTP", "value": "T1566.001"}
        result = classify_claim_for_verification(claim)
        assert result["strategy"] == "attack_lookup"

    def test_attribution_claim_routes_to_multi_source(self):
        claim = {"claim_type": "ATTRIBUTION", "actor": "APT29"}
        result = classify_claim_for_verification(claim)
        assert result["strategy"] == "multi_source_verification"


class TestAggregateResults:
    """Aggregate verification results into final report."""

    def test_aggregate_all_verified(self):
        results = [
            {"claim_id": "C1", "verification_status": "VERIFIED_HIGH", "confidence_score": 0.95},
            {"claim_id": "C2", "verification_status": "VERIFIED_MEDIUM", "confidence_score": 0.75},
        ]
        summary = aggregate_verification_results(results)
        assert summary["total"] == 2
        assert summary["verified_high"] == 1
        assert summary["verified_medium"] == 1
        assert summary["pass_rate"] == 1.0

    def test_aggregate_with_refuted(self):
        results = [
            {"claim_id": "C1", "verification_status": "VERIFIED_HIGH", "confidence_score": 0.95},
            {"claim_id": "C2", "verification_status": "REFUTED", "confidence_score": 0.0},
        ]
        summary = aggregate_verification_results(results)
        assert summary["refuted"] == 1
        assert summary["pass_rate"] == 0.5


class TestHallucinationDetection:
    """Detect patterns suggesting fabricated claims."""

    def test_detects_no_source_pattern(self):
        claims = [
            {"claim_id": "C1", "sources_checked": [], "verification_status": "UNVERIFIED"},
        ]
        flags = detect_hallucination_patterns(claims)
        assert len(flags) >= 1
        assert "C1" in flags[0]

    def test_detects_all_refuted_pattern(self):
        claims = [
            {"claim_id": "C1", "sources_checked": ["gti"], "verification_status": "REFUTED"},
            {"claim_id": "C2", "sources_checked": ["gti"], "verification_status": "REFUTED"},
            {"claim_id": "C3", "sources_checked": ["gti"], "verification_status": "REFUTED"},
        ]
        flags = detect_hallucination_patterns(claims)
        assert any("high refutation rate" in f.lower() for f in flags)

    def test_no_flags_when_all_verified(self):
        claims = [
            {"claim_id": "C1", "sources_checked": ["gti"], "verification_status": "VERIFIED_HIGH"},
        ]
        flags = detect_hallucination_patterns(claims)
        assert len(flags) == 0
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_verification_pipeline.py -q`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

```python
"""Verification pipeline for CTI Agent multi-agent team.

Extracts verifiable claims from assessment packages, routes them to
appropriate verification strategies, and detects hallucination patterns.
Used by the Verifier agent to independently validate all claims.
"""

import re

# IOC type to MCP server routing for verification
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

    # Extract IOC claims from Diamond Model infrastructure
    diamond = assessment.get("diamond_model", {})
    infra = diamond.get("infrastructure", {})
    for ioc in infra.get("iocs", []):
        claim_counter += 1
        claims.append({
            "claim_id": f"C{claim_counter}",
            "claim_type": "IOC",
            "ioc_type": ioc.get("type", "unknown"),
            "value": ioc.get("value", ""),
            "original_claim": f"IOC {ioc.get('value', '')} observed in infrastructure",
        })

    # Extract TTP claims
    for ttp in assessment.get("ttps_identified", []):
        claim_counter += 1
        claims.append({
            "claim_id": f"C{claim_counter}",
            "claim_type": "TTP",
            "value": ttp,
            "original_claim": f"Technique {ttp} identified in attack",
        })

    # Extract attribution claims from key judgments
    for judgment in assessment.get("key_judgments", []):
        statement = judgment.get("statement", "")
        attribution_pattern = re.compile(
            r"(APT\d+|FIN\d+|Lazarus|Cozy Bear|Fancy Bear|\w+\s+Group)",
            re.IGNORECASE,
        )
        match = attribution_pattern.search(statement)
        if match:
            claim_counter += 1
            claims.append({
                "claim_id": f"C{claim_counter}",
                "claim_type": "ATTRIBUTION",
                "actor": match.group(0),
                "value": match.group(0),
                "original_claim": statement,
            })

    # Extract actor from Diamond Model adversary
    adversary = diamond.get("adversary", {})
    if adversary.get("name"):
        claim_counter += 1
        claims.append({
            "claim_id": f"C{claim_counter}",
            "claim_type": "ATTRIBUTION",
            "actor": adversary["name"],
            "value": adversary["name"],
            "original_claim": f"Activity attributed to {adversary['name']}",
        })

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

    counts = {
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

    passed = counts["verified_high"] + counts["verified_medium"] + counts["verified_low"]
    return {
        "total": total,
        **counts,
        "pass_rate": passed / total,
    }


def detect_hallucination_patterns(claims: list[dict]) -> list[str]:
    """Detect patterns suggesting fabricated or hallucinated claims."""
    flags = []

    # Flag claims with no sources checked
    for claim in claims:
        if not claim.get("sources_checked"):
            flags.append(
                f"{claim['claim_id']}: No sources checked — possible fabrication"
            )

    # Flag high refutation rate
    if claims:
        refuted = sum(
            1 for c in claims if c.get("verification_status") == "REFUTED"
        )
        rate = refuted / len(claims)
        if rate >= REFUTATION_RATE_THRESHOLD:
            flags.append(
                f"High refutation rate ({rate:.0%}) across {len(claims)} claims — "
                f"possible systematic hallucination"
            )

    return flags
```

**Step 4: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_verification_pipeline.py -q`
Expected: 10 passed

**Step 5: Lint and commit**

```bash
cd "/home/ryantreb/Security Projects/CTI_agent" && ruff check lib/verification_pipeline.py tests/test_verification_pipeline.py --fix && ruff format lib/verification_pipeline.py tests/test_verification_pipeline.py
git add tests/test_verification_pipeline.py lib/verification_pipeline.py
git commit -m "feat: add verification pipeline with hallucination detection"
```

---

## Task 6: Agent Definition — Collector

**Files:**
- Create: `agents/definitions/collector.md`
- Create: `agents/README.md`

**Step 1: Create the agents directory and Collector definition**

Create `agents/README.md`:

```markdown
# CTI Agent Agent Definitions

Agent role definitions for the multi-agent intelligence team (v2.4.0).

| Agent | File | Role |
|-------|------|------|
| Collector | `definitions/collector.md` | Parallel feed monitoring and IOC enrichment |
| Analyst | `definitions/analyst.md` | Diamond Model analysis, ACH, hypothesis generation |
| Devil's Advocate | `definitions/devils_advocate.md` | Adversarial challenge of assessments |
| Verifier | `definitions/verifier.md` | Independent claim validation |
| Reporter | `definitions/reporter.md` | Final product assembly |

## Pipeline Flow

```
Collector → Analyst → [Devil's Advocate ↔ Analyst debate] → Verifier → Reporter
```

## Data Handoffs

| From | To | Data Structure |
|------|----|---------------|
| Collector | Analyst | `collection_bundle` |
| Analyst | Devil's Advocate | `assessment_package` |
| DA ↔ Analyst | Verifier | `debate_record` |
| Verifier | Reporter | `verification_report` |
```

Create `agents/definitions/collector.md`:

```markdown
---
name: collector
role: intelligence-collector
skills:
  - check-server-health
  - monitor-feeds
  - enrich-iocs
  - recall-intelligence
mandate: Parallel feed monitoring and IOC enrichment across all MCP servers
---

# Collector Agent

## Role
Gather raw intelligence from all configured MCP sources, enrich IOCs through multi-source routing, and package results for the Analyst.

## Execution Protocol

### Step 1: Health Check
```
CALL check-server-health
RECORD available servers and degraded capabilities
```

### Step 2: Historical Context
```
CALL recall-intelligence with session context
EXTRACT prior relevant reports, known actors, active campaigns
```

### Step 3: Feed Collection
```
CALL monitor-feeds
COLLECT from ALL available sources in parallel:
  - Feedly threat intelligence
  - GTI threat collections
  - AlienVault OTX pulses
  - ORKL threat reports
  - Mallory real-time threats (if available)
  - TI Mindmap HUB analysis
  - CVE intelligence (NVD + KEV + EPSS)
DEDUPLICATE against state/processed_guids.json
```

### Step 4: IOC Enrichment
```
CALL enrich-iocs for ALL items in enrichment queue
USE dynamic routing from check-server-health results
ENRICH in priority order: P1 → P2 → P3 → P4 → P5
```

### Step 5: Package Results
```
BUILD collection_bundle (lib/team_data.create_collection_bundle)
INCLUDE:
  - All enriched IOCs with confidence scores
  - Raw intelligence items
  - Sources queried and sources unavailable
  - Historical context from recall-intelligence
HANDOFF to Analyst
```

## Constraints
- NEVER analyze or assess — only collect and enrich
- NEVER fabricate IOCs — only report what sources return
- Log all MCP calls to logs/{date}.jsonl
- Record metrics via lib/metrics.append_metric
- Respect rate limits per enrich-iocs skill
```

**Step 2: Commit**

```bash
mkdir -p "/home/ryantreb/Security Projects/CTI_agent/agents/definitions"
git add agents/README.md agents/definitions/collector.md
git commit -m "feat: add Collector agent definition"
```

---

## Task 7: Agent Definition — Analyst

**Files:**
- Create: `agents/definitions/analyst.md`

**Step 1: Create Analyst definition**

```markdown
---
name: analyst
role: intelligence-analyst
skills:
  - diamond-model-analysis
  - analysis-competing-hypotheses
  - recall-intelligence
mandate: Structure analysis using Diamond Model, generate hypotheses via ACH, produce calibrated assessments
---

# Analyst Agent

## Role
Transform collected intelligence into structured analytical products using Diamond Model and ACH frameworks. Produce calibrated key judgments per ICD 203 standards.

## Execution Protocol

### Step 1: Receive Collection Bundle
```
RECEIVE collection_bundle from Collector
EXTRACT enriched IOCs, raw items, historical context
CATEGORIZE by: threat actors, campaigns, TTPs, infrastructure
```

### Step 2: Diamond Model Analysis
```
CALL diamond-model-analysis
FOR EACH campaign/cluster identified:
  1. Initialize Diamond Event
  2. Populate Adversary vertex (from actor profiles + enrichment)
  3. Populate Infrastructure vertex (from IOC enrichment)
  4. Populate Capability vertex (TTPs + malware families)
  5. Populate Victim vertex (targeting context)
  6. Perform analytical pivoting (6 directions)
  7. Build activity threads by Kill Chain phase
```

### Step 3: ACH Analysis (for attribution)
```
CALL analysis-competing-hypotheses
IF attribution is uncertain:
  1. Generate ≥3 hypotheses (including deception + null)
  2. List ALL evidence from Diamond Model
  3. Create diagnosticity matrix
  4. Score hypotheses (focus on refuting, not confirming)
  5. Document assessment with confidence levels
```

### Step 4: Generate Key Judgments
```
FOR EACH significant finding:
  CREATE key_judgment (lib/team_data.create_key_judgment):
    - Statement using ICD 203 probability language
    - Confidence level (calibrated per evidence)
    - Supporting evidence (with sources)
    - Contradicting evidence
    - Assumptions
```

### Step 5: Package Assessment
```
BUILD assessment_package (lib/team_data.create_assessment_package):
  - Diamond Model output
  - ACH result (if attribution assessed)
  - Key judgments list
  - TTPs identified
  - Actor profiles referenced
  - Intelligence gaps
HANDOFF to Devil's Advocate
```

## Constraints
- EVERY judgment MUST use ICD 203 confidence language
- NEVER overclaim certainty — calibrate to evidence
- Document ALL assumptions explicitly
- Include intelligence gaps (what we don't know)
- Reference actor profiles from actors/ directory
- Record metrics for analysis steps
```

**Step 2: Commit**

```bash
git add agents/definitions/analyst.md
git commit -m "feat: add Analyst agent definition"
```

---

## Task 8: Agent Definition — Devil's Advocate

**Files:**
- Create: `agents/definitions/devils_advocate.md`

**Step 1: Create Devil's Advocate definition**

```markdown
---
name: devils-advocate
role: adversarial-reviewer
skills:
  - analysis-competing-hypotheses
mandate: Systematically challenge the Analyst's assessments to reduce confirmation bias and strengthen analytical rigor
---

# Devil's Advocate Agent

## Role
Structural mandate to argue AGAINST the Analyst's leading hypothesis. Forces the Analyst to justify high-confidence assessments and ensures alternative interpretations are documented per ICD 203.

## Execution Protocol

### Step 1: Receive Assessment Package
```
RECEIVE assessment_package from Analyst
EXTRACT key_judgments, evidence_matrix, Diamond Model, ACH result
```

### Step 2: Identify Mandatory Challenges
```
FOR EACH key_judgment:
  IF confidence IN ("highly likely", "almost certain"):
    MUST challenge — this is non-negotiable
  IF confidence == "likely" AND attribution claim:
    SHOULD challenge

USE lib/debate.should_challenge() to determine mandatory challenges
USE lib/debate.generate_challenge_types() to determine challenge strategy
```

### Step 3: Construct Challenges
```
FOR EACH judgment requiring challenge:
  1. ARGUE for the second-most-likely hypothesis
  2. IDENTIFY evidence the Analyst may have underweighted
  3. PROPOSE at least ONE alternative interpretation
  4. QUANTIFY proposed confidence adjustment
  5. BUILD challenge (lib/team_data.create_challenge)

CHALLENGE TYPES:
  - alternative_hypothesis: Argue for a different actor/motive/method
  - evidence_underweighted: Highlight contradicting evidence that was minimized
  - source_reliability: Question reliability of key sources
  - deception_hypothesis: Propose the adversary staged evidence
  - assumption_challenge: Challenge key assumptions
```

### Step 4: Debate Loop
```
SEND challenges to Analyst
RECEIVE analyst_responses

FOR EACH response:
  IF accepted: Note adjustment
  IF rejected: EVALUATE rebuttal
    IF rebuttal is weak: ESCALATE with additional counter-evidence
    IF rebuttal is strong: ACCEPT with documented dissent

CHECK consensus via lib/debate.check_consensus()
IF NOT consensus AND round < MAX_ROUNDS:
  REPEAT Step 3-4 with refined challenges
IF MAX_ROUNDS reached:
  DOCUMENT all unresolved disagreements as dissenting views
```

### Step 5: Package Debate Record
```
BUILD debate_record (lib/team_data.create_debate_record):
  - Original assessment_package
  - All challenges raised
  - All analyst responses
  - Rounds completed
  - Consensus status
  - Final (possibly revised) judgments
  - Dissenting views (if any)
HANDOFF to Verifier
```

## Constraints (IMMUTABLE)
- MUST challenge ALL assessments rated "highly likely" or above
- MUST argue for the second-most-likely hypothesis (not fabricate)
- MUST propose at least ONE alternative interpretation per challenged judgment
- NEVER agree with the Analyst without providing counter-arguments first
- ALWAYS document disagreements even if consensus is reached
- Maximum 3 debate rounds before forcing documentation of dissent
```

**Step 2: Commit**

```bash
git add agents/definitions/devils_advocate.md
git commit -m "feat: add Devil's Advocate agent definition"
```

---

## Task 9: Agent Definition — Verifier

**Files:**
- Create: `agents/definitions/verifier.md`

**Step 1: Create Verifier definition**

```markdown
---
name: verifier
role: independent-verifier
skills:
  - verify-claims
mandate: Independently re-validate ALL claims from the debate output before report generation — no hallucinated IOCs pass through
---

# Verifier Agent

## Role
Independent fact-checking of ALL claims (IOCs, TTPs, attributions) from the Analyst-Devil's Advocate debate. Re-queries source APIs via MCP servers. Only Verifier-approved content reaches the Reporter.

## Execution Protocol

### Step 1: Receive Debate Record
```
RECEIVE debate_record from Devil's Advocate ↔ Analyst exchange
EXTRACT:
  - Final key judgments (post-debate, possibly revised)
  - All IOC claims from Diamond Model
  - All TTP claims
  - All attribution claims
```

### Step 2: Extract All Verifiable Claims
```
USE lib/verification_pipeline.extract_claims_from_assessment()
ON the debate_record's assessment_package

CLASSIFY each claim:
  - IOC → mcp_verification (re-query source APIs)
  - TTP → attack_lookup (validate technique ID exists)
  - ATTRIBUTION → multi_source_verification (check multiple sources)

USE lib/verification_pipeline.classify_claim_for_verification()
```

### Step 3: Independent Re-Verification
```
FOR EACH claim:
  CALL verify-claims skill with the claim
  DO NOT trust upstream verification results — re-query independently

  IF IOC claim:
    QUERY appropriate MCP servers (gti, shodan, mcp-threatintel, etc.)
    COMPARE returned attributes against claimed attributes
    ASSIGN verification status: VERIFIED_HIGH/MEDIUM/LOW, UNVERIFIED, REFUTED

  IF TTP claim:
    VERIFY technique ID exists in ATT&CK framework
    VERIFY tactic-technique mapping is correct

  IF ATTRIBUTION claim:
    QUERY multiple sources (gti, otx, orkl, mallory)
    CHECK actor name, aliases, known TTPs match
    FLAG any attribution not supported by ≥2 independent sources
```

### Step 4: Hallucination Detection
```
USE lib/verification_pipeline.detect_hallucination_patterns()
FLAG:
  - Claims with NO source verification possible
  - High refutation rate (≥50% claims refuted)
  - IOCs that don't appear in ANY queried database
  - Attribution claims supported by only 1 source
```

### Step 5: Package Verification Report
```
BUILD verification_report (lib/team_data.create_verification_report):
  - Verified claims (with confidence scores)
  - Refuted claims (EXCLUDED from reporter input)
  - Unverified claims (FLAGGED for reporter)
  - Hallucination flags

AGGREGATE results via lib/verification_pipeline.aggregate_verification_results()
HANDOFF to Reporter (ONLY verified + unverified content; NEVER refuted)
```

## Constraints (IMMUTABLE)
- NEVER trust upstream verification — always re-verify independently
- NEVER pass REFUTED claims to Reporter
- UNVERIFIED claims MUST carry [UNVERIFIED] prefix
- ALL API calls logged with timestamps
- Verification latency budget: <5 seconds per claim
- REFUTED claims quarantined with explanation
```

**Step 2: Commit**

```bash
git add agents/definitions/verifier.md
git commit -m "feat: add Verifier agent definition"
```

---

## Task 10: Agent Definition — Reporter

**Files:**
- Create: `agents/definitions/reporter.md`

**Step 1: Create Reporter definition**

```markdown
---
name: reporter
role: intelligence-reporter
skills:
  - generate-report
  - produce-stix-bundle
  - produce-attack-layers
mandate: Assemble verified, challenged intelligence into final deliverables — reports, STIX bundles, ATT&CK layers
---

# Reporter Agent

## Role
Produce final intelligence products from Verifier-approved content only. Generates markdown reports, STIX 2.1 bundles, ATT&CK Navigator layers, and detection artifacts.

## Execution Protocol

### Step 1: Receive Verification Report
```
RECEIVE verification_report from Verifier
EXTRACT:
  - Verified claims (include in report)
  - Unverified claims (include with [UNVERIFIED] prefix)
  - Hallucination flags (note in report metadata)
  - REFUTED claims are NOT present — Verifier excluded them
```

### Step 2: Receive Debate Record
```
RECEIVE debate_record from Devil's Advocate exchange
EXTRACT:
  - Final key judgments (post-debate versions)
  - Alternative Analysis content
  - Dissenting views
USE lib/debate.build_alternative_analysis_section() for report
```

### Step 3: Generate Intelligence Report
```
CALL generate-report skill
PRODUCE report with ALL required sections:
  1. Classification header (TLP, confidence, validity)
  2. Executive summary
  3. Key Judgments (using post-debate versions)
  4. Diamond Model summary
  5. Kill Chain / ATT&CK mapping
  6. ACH Summary (if attribution assessed)
  7. **Alternative Analysis** (from debate record)
  8. IOC tables (verified only, defanged)
  9. Defensive recommendations (≥3)
  10. Key assumptions
  11. Intelligence gaps
  12. Reassessment triggers
  13. Sources with reliability

APPLY verification-based confidence:
  - VERIFIED_HIGH → include as stated
  - VERIFIED_MEDIUM → include with caveat
  - VERIFIED_LOW → include with strong caveat
  - UNVERIFIED → prefix [UNVERIFIED]
```

### Step 4: Generate STIX Bundle
```
CALL produce-stix-bundle skill
INPUT: Diamond Model output (verified content only)
OUTPUT: reports/{guid}_stix_bundle.json
```

### Step 5: Generate ATT&CK Layer
```
CALL produce-attack-layers skill
INPUT: Diamond Model capability vertex (verified TTPs)
OUTPUT: reports/{guid}_attack_layer.json
```

### Step 6: Generate Detection Artifacts
```
DELEGATE per config/skill_ownership.json:
  - YARA rules → external/yara-rule-skill
  - Sigma rules → external/malware-analysis/detection-engineer
OUTPUT: reports/{guid}_detections/
```

### Step 7: Record Metrics
```
RECORD via lib/metrics:
  - claims_verified, claims_refuted, claims_unverified
  - debate_rounds, consensus_reached
  - report_type, output_files
```

## Constraints
- ONLY include Verifier-approved content
- NEVER fabricate or embellish findings
- ALL judgments use ICD 203 confidence language
- Include Alternative Analysis section (per debate record)
- Include dissenting views when consensus not reached
- Defang ALL IOCs in report text
```

**Step 2: Commit**

```bash
git add agents/definitions/reporter.md
git commit -m "feat: add Reporter agent definition"
```

---

## Task 11: Team Orchestration Skill

**Files:**
- Create: `skills/orchestrate-team/SKILL.md`

**Step 1: Create the orchestration skill**

```markdown
---
name: orchestrate-team
description: Coordinate the 5-agent intelligence team pipeline (Collector → Analyst → Devil's Advocate ↔ Analyst → Verifier → Reporter). Use when running a full intelligence analysis session with adversarial review and independent verification.
---

# Team Orchestration Skill

## Purpose
Coordinate the multi-agent intelligence team to execute a full analysis pipeline with adversarial challenge and independent verification.

## Team Composition

| Agent | Definition | Role |
|-------|-----------|------|
| Collector | `agents/definitions/collector.md` | Gather and enrich intelligence |
| Analyst | `agents/definitions/analyst.md` | Analyze and assess |
| Devil's Advocate | `agents/definitions/devils_advocate.md` | Challenge assessments |
| Verifier | `agents/definitions/verifier.md` | Validate all claims |
| Reporter | `agents/definitions/reporter.md` | Produce deliverables |

## Pipeline Flow

```
Phase 1: COLLECT
  Collector agent executes:
    check-server-health → recall-intelligence → monitor-feeds → enrich-iocs
  OUTPUT: collection_bundle

Phase 2: ANALYZE
  Analyst agent executes:
    diamond-model-analysis → analysis-competing-hypotheses
  OUTPUT: assessment_package

Phase 3: DEBATE
  Devil's Advocate ↔ Analyst exchange:
    FOR round IN 1..MAX_ROUNDS:
      DA constructs challenges (lib/debate)
      Analyst responds with rebuttals/adjustments
      CHECK consensus (lib/debate.check_consensus)
      IF consensus: BREAK
    DOCUMENT dissenting views
  OUTPUT: debate_record

Phase 4: VERIFY
  Verifier agent executes:
    extract_claims → classify_claims → verify-claims → detect_hallucinations
  OUTPUT: verification_report

Phase 5: REPORT
  Reporter agent executes:
    generate-report → produce-stix-bundle → produce-attack-layers
  OUTPUT: Final deliverables
```

## Execution Protocol

### Step 1: Initialize Team Session
```
GENERATE session_id (UUID)
LOG team_session_start to logs/{date}.jsonl
LOAD team config from config/team_config.json
```

### Step 2: Execute Collection Phase
```
ACTIVATE Collector agent (agents/definitions/collector.md)
WAIT for collection_bundle output
VALIDATE: collection_bundle has enriched_iocs
IF empty: LOG "no new intelligence", SKIP to metrics
```

### Step 3: Execute Analysis Phase
```
ACTIVATE Analyst agent (agents/definitions/analyst.md)
PASS: collection_bundle
WAIT for assessment_package output
VALIDATE: assessment_package has key_judgments
```

### Step 4: Execute Debate Phase
```
ACTIVATE Devil's Advocate agent (agents/definitions/devils_advocate.md)
PASS: assessment_package

DEBATE LOOP:
  DA generates challenges
  PASS challenges to Analyst for response
  Analyst provides rebuttals/adjustments
  CHECK consensus
  IF consensus OR round >= 3: EXIT loop

CAPTURE debate_record
```

### Step 5: Execute Verification Phase
```
ACTIVATE Verifier agent (agents/definitions/verifier.md)
PASS: debate_record (includes assessment_package)
WAIT for verification_report
LOG: verified_count, refuted_count, hallucination_flags
```

### Step 6: Execute Reporting Phase
```
ACTIVATE Reporter agent (agents/definitions/reporter.md)
PASS: verification_report + debate_record
WAIT for final outputs:
  - reports/{guid}.md
  - reports/{guid}_stix_bundle.json
  - reports/{guid}_attack_layer.json
  - reports/{guid}_detections/
```

### Step 7: Finalize Session
```
RECORD session metrics via lib/metrics
UPDATE state files
LOG team_session_end
```

## Error Handling

| Failure | Recovery |
|---------|----------|
| Collector returns empty | Log, skip session gracefully |
| Analyst fails | Log error, attempt with reduced input |
| Debate exceeds MAX_ROUNDS | Force document dissent, continue to Verifier |
| Verifier API errors | Mark claims UNVERIFIED, continue |
| Reporter fails | Log, save partial outputs |
| Any agent crash | Log, save state, alert user |

## Rationale

This pipeline addresses two critical LLM failure modes:
1. **Confirmation bias**: Devil's Advocate has structural mandate to challenge
2. **Hallucination**: Verifier independently re-validates every claim against source APIs
```

**Step 2: Commit**

```bash
git add skills/orchestrate-team/SKILL.md
git commit -m "feat: add team orchestration skill for 5-agent pipeline"
```

---

## Task 12: Team Configuration

**Files:**
- Create: `config/team_config.json`

**Step 1: Create team configuration**

```json
{
  "schema_version": "1.0",
  "team_name": "cti-intelligence-team",
  "version": "2.4.0",
  "agents": [
    {
      "name": "collector",
      "definition": "agents/definitions/collector.md",
      "role": "intelligence-collector",
      "skills": ["check-server-health", "monitor-feeds", "enrich-iocs", "recall-intelligence"],
      "pipeline_position": 1,
      "receives_from": null,
      "sends_to": "analyst"
    },
    {
      "name": "analyst",
      "definition": "agents/definitions/analyst.md",
      "role": "intelligence-analyst",
      "skills": ["diamond-model-analysis", "analysis-competing-hypotheses", "recall-intelligence"],
      "pipeline_position": 2,
      "receives_from": "collector",
      "sends_to": "devils-advocate"
    },
    {
      "name": "devils-advocate",
      "definition": "agents/definitions/devils_advocate.md",
      "role": "adversarial-reviewer",
      "skills": ["analysis-competing-hypotheses"],
      "pipeline_position": 3,
      "receives_from": "analyst",
      "sends_to": "verifier",
      "debate_partner": "analyst",
      "max_debate_rounds": 3
    },
    {
      "name": "verifier",
      "definition": "agents/definitions/verifier.md",
      "role": "independent-verifier",
      "skills": ["verify-claims"],
      "pipeline_position": 4,
      "receives_from": "devils-advocate",
      "sends_to": "reporter"
    },
    {
      "name": "reporter",
      "definition": "agents/definitions/reporter.md",
      "role": "intelligence-reporter",
      "skills": ["generate-report", "produce-stix-bundle", "produce-attack-layers"],
      "pipeline_position": 5,
      "receives_from": "verifier",
      "sends_to": null
    }
  ],
  "pipeline": [
    {"phase": "collect", "agent": "collector", "output": "collection_bundle"},
    {"phase": "analyze", "agent": "analyst", "output": "assessment_package"},
    {"phase": "debate", "agents": ["devils-advocate", "analyst"], "output": "debate_record"},
    {"phase": "verify", "agent": "verifier", "output": "verification_report"},
    {"phase": "report", "agent": "reporter", "output": "final_deliverables"}
  ],
  "data_handoffs": {
    "collection_bundle": {"from": "collector", "to": "analyst"},
    "assessment_package": {"from": "analyst", "to": "devils-advocate"},
    "debate_record": {"from": "devils-advocate", "to": "verifier"},
    "verification_report": {"from": "verifier", "to": "reporter"}
  }
}
```

**Step 2: Commit**

```bash
git add config/team_config.json
git commit -m "feat: add team configuration for 5-agent pipeline"
```

---

## Task 13: Update AGENT.md to v2.4.0

**Files:**
- Modify: `AGENT.md`

**Step 1: Update version and add multi-agent team section**

Changes to make in `AGENT.md`:

1. Change `**Version**: 2.3.0` → `**Version**: 2.4.0`

2. Add `orchestrate-team` to the Skill Registry table:

```markdown
| `orchestrate-team` | Coordinate 5-agent intelligence team pipeline | 0 (wraps all) | All skills |
```

3. Add new section after "Self-Modification Safety Protocol" and before "MCP Server Registry":

```markdown
## Multi-Agent Team

### Team Composition (5 agents)

| Agent | Role | Skills Used | Mandate |
|-------|------|------------|---------|
| **Collector** | Gather raw intelligence | monitor-feeds, enrich-iocs | Parallel feed monitoring and IOC enrichment across all MCP servers |
| **Analyst** | Produce assessments | diamond-model, ACH, recall-intelligence | Structure analysis and generate hypotheses |
| **Devil's Advocate** | Challenge assessments | ACH (adversarial mode) | Systematically argue against the Analyst's leading hypothesis |
| **Verifier** | Validate all claims | verify-claims | Independent fact-checking of ALL claims before report generation |
| **Reporter** | Produce final products | generate-report, produce-stix-bundle, produce-attack-layers | Assemble verified, challenged intelligence into final deliverables |

### Pipeline

```
Collector → Analyst → [Devil's Advocate ↔ Analyst debate] → Verifier → Reporter
```

### Devil's Advocate Protocol

1. MUST challenge ALL assessments rated "highly likely" or above
2. MUST argue for the second-most-likely hypothesis
3. Proposes at least one alternative interpretation per key judgment
4. Maximum 3 debate rounds before documenting dissent
5. Disagreements documented in report's "Alternative Analysis" section (per ICD 203)

### Verifier Protocol

1. Independently re-queries all cited sources via MCP servers
2. Confirms every IOC, TTP, and attribution claim exists in source data
3. Flags claims that cannot be independently verified
4. REFUTED claims excluded from Reporter input
5. Hallucination patterns detected and flagged
```

4. Update footer: `*CTI Agent v2.4.0 — ...*`

**Step 2: Commit**

```bash
git add AGENT.md
git commit -m "feat: update AGENT.md to v2.4.0 with multi-agent team"
```

---

## Task 14: Update skill_versions.json

**Files:**
- Modify: `state/skill_versions.json`

**Step 1: Add orchestrate-team to skill versions**

Add to the `"skills"` object:

```json
"orchestrate-team": {
  "current_version": 0,
  "versions": [
    {
      "version": 0,
      "timestamp": null,
      "status": "baseline",
      "eval_scores": {},
      "prompt_hash": null
    }
  ]
}
```

**Step 2: Commit**

```bash
git add -f state/skill_versions.json
git commit -m "feat: add orchestrate-team to skill version tracking"
```

---

## Task 15: Integration Tests

**Files:**
- Modify: `tests/test_integration.py`

**Step 1: Add Phase 4 integration tests**

Add to end of `tests/test_integration.py`:

```python
# --- Phase 4 Tests ---


class TestTeamDataSchemas:
    """Inter-agent data schemas are valid."""

    def test_collection_bundle_creation(self):
        from lib.team_data import create_collection_bundle, create_enriched_ioc

        ioc = create_enriched_ioc(
            ioc_type="ip", value="10.0.0.1", confidence=0.85, sources=["gti"]
        )
        bundle = create_collection_bundle(
            session_id="test", sources_queried=["feedly"], enriched_iocs=[ioc]
        )
        assert bundle["type"] == "collection_bundle"
        assert bundle["ioc_count"] == 1

    def test_assessment_package_creation(self):
        from lib.team_data import create_assessment_package, create_key_judgment

        judgment = create_key_judgment(
            judgment_id="KJ1",
            statement="Test",
            confidence="likely",
            confidence_numeric=0.70,
        )
        package = create_assessment_package(
            session_id="test",
            diamond_model={},
            ach_result={},
            key_judgments=[judgment],
        )
        assert package["type"] == "assessment_package"

    def test_debate_record_creation(self):
        from lib.team_data import create_debate_record, create_challenge

        challenge = create_challenge(
            target_judgment_id="KJ1",
            challenge_type="alternative_hypothesis",
            argument="Test challenge",
            counter_evidence=["E1"],
        )
        record = create_debate_record(
            session_id="test",
            assessment_package={},
            challenges=[challenge],
            rounds_completed=1,
            consensus_reached=True,
        )
        assert record["type"] == "debate_record"

    def test_verification_report_creation(self):
        from lib.team_data import create_verification_report, create_verified_claim

        claim = create_verified_claim(
            claim_id="C1",
            original_claim="Test",
            claim_type="IOC",
            verification_status="VERIFIED_HIGH",
            confidence_score=0.95,
            sources_checked=["gti"],
        )
        report = create_verification_report(
            session_id="test",
            verified_claims=[claim],
            refuted_claims=[],
            unverified_claims=[],
        )
        assert report["type"] == "verification_report"
        assert report["total_claims"] == 1


class TestDebateEngine:
    """Debate engine enforces adversarial review rules."""

    def test_mandatory_challenge_thresholds(self):
        from lib.debate import should_challenge

        assert should_challenge({"confidence": "highly likely"}) is True
        assert should_challenge({"confidence": "almost certain"}) is True
        assert should_challenge({"confidence": "likely"}) is False

    def test_consensus_detection(self):
        from lib.debate import check_consensus

        result = check_consensus(challenges=[], analyst_responses=[], round_num=1)
        assert result["consensus"] is True

    def test_alternative_analysis_generation(self):
        from lib.debate import build_alternative_analysis_section

        record = {
            "challenges": [{"target_judgment_id": "KJ1", "argument": "Test", "counter_evidence": []}],
            "analyst_responses": [],
            "consensus_reached": False,
            "dissenting_views": ["Test dissent"],
        }
        section = build_alternative_analysis_section(record)
        assert "Alternative Analysis" in section


class TestVerificationPipeline:
    """Verification pipeline extracts and classifies claims."""

    def test_extract_ioc_claims(self):
        from lib.verification_pipeline import extract_claims_from_assessment

        assessment = {
            "diamond_model": {
                "infrastructure": {
                    "iocs": [{"type": "ipv4-addr", "value": "10.0.0.1"}]
                }
            },
            "key_judgments": [],
        }
        claims = extract_claims_from_assessment(assessment)
        assert len(claims) >= 1

    def test_classify_ioc_for_verification(self):
        from lib.verification_pipeline import classify_claim_for_verification

        claim = {"claim_type": "IOC", "ioc_type": "ipv4-addr"}
        result = classify_claim_for_verification(claim)
        assert result["strategy"] == "mcp_verification"

    def test_hallucination_detection(self):
        from lib.verification_pipeline import detect_hallucination_patterns

        claims = [
            {"claim_id": "C1", "sources_checked": [], "verification_status": "UNVERIFIED"},
        ]
        flags = detect_hallucination_patterns(claims)
        assert len(flags) >= 1


class TestAgentDefinitions:
    """Agent definition files exist and are valid."""

    def test_all_agent_definitions_exist(self):
        agents_dir = PROJECT_ROOT / "agents" / "definitions"
        expected = ["collector.md", "analyst.md", "devils_advocate.md", "verifier.md", "reporter.md"]
        for agent_file in expected:
            assert (agents_dir / agent_file).exists(), f"Missing agent definition: {agent_file}"

    def test_agent_definitions_have_frontmatter(self):
        agents_dir = PROJECT_ROOT / "agents" / "definitions"
        for md_file in agents_dir.glob("*.md"):
            content = md_file.read_text()
            assert content.startswith("---"), f"{md_file.name} missing frontmatter"


class TestTeamConfig:
    """Team configuration is valid."""

    def test_team_config_exists(self):
        config_file = CONFIG_DIR / "team_config.json"
        assert config_file.exists()

    def test_team_config_has_5_agents(self):
        with open(CONFIG_DIR / "team_config.json") as f:
            config = json.load(f)
        assert len(config["agents"]) == 5

    def test_team_config_pipeline_order(self):
        with open(CONFIG_DIR / "team_config.json") as f:
            config = json.load(f)
        pipeline_agents = [p["agent"] if "agent" in p else p["agents"][0] for p in config["pipeline"]]
        assert pipeline_agents == ["collector", "analyst", "devils-advocate", "verifier", "reporter"]

    def test_orchestrate_team_skill_exists(self):
        skill_file = SKILLS_DIR / "orchestrate-team" / "SKILL.md"
        assert skill_file.exists()
```

Also update the version test:

Change `assert "**Version**: 2.3.0" in agent_md` to `assert "**Version**: 2.4.0" in agent_md`

**Step 2: Run all tests**

Run: `uv run --with pytest python -m pytest tests/ -q`
Expected: All tests pass (previous 129 + new ~19 = ~148)

**Step 3: Commit and tag**

```bash
git add tests/test_integration.py
git commit -m "feat: add Phase 4 integration tests and update version to v2.4.0"
git tag v2.4.0
```

---

## Summary

| Task | Component | Tests | Files |
|------|-----------|-------|-------|
| 1 | Collection Bundle schema | 4 | `lib/team_data.py`, `tests/test_team_data.py` |
| 2 | Assessment Package schema | 3 | `lib/team_data.py` |
| 3 | Debate Record + Verification Report | 6 | `lib/team_data.py` |
| 4 | Debate Engine | 10 | `lib/debate.py`, `tests/test_debate.py` |
| 5 | Verification Pipeline | 10 | `lib/verification_pipeline.py`, `tests/test_verification_pipeline.py` |
| 6 | Collector agent | — | `agents/definitions/collector.md` |
| 7 | Analyst agent | — | `agents/definitions/analyst.md` |
| 8 | Devil's Advocate agent | — | `agents/definitions/devils_advocate.md` |
| 9 | Verifier agent | — | `agents/definitions/verifier.md` |
| 10 | Reporter agent | — | `agents/definitions/reporter.md` |
| 11 | Orchestration skill | — | `skills/orchestrate-team/SKILL.md` |
| 12 | Team config | — | `config/team_config.json` |
| 13 | AGENT.md v2.4.0 | — | `AGENT.md` |
| 14 | Skill versions | — | `state/skill_versions.json` |
| 15 | Integration tests | ~19 | `tests/test_integration.py` |

**Total new unit tests:** ~33
**Total new integration tests:** ~19
**Total new files:** 11
**Total modified files:** 4

"""Tests for inter-agent data schemas."""

from lib.team_data import (
    create_assessment_package,
    create_challenge,
    create_collection_bundle,
    create_debate_record,
    create_enriched_ioc,
    create_key_judgment,
    create_verification_report,
    create_verified_claim,
)


class TestCollectionBundle:
    """Collection bundle data structure for Collector → Analyst handoff."""

    def test_create_collection_bundle_minimal(self):
        bundle = create_collection_bundle(
            session_id="test-session",
            sources_queried=["gti", "otx"],
        )
        assert bundle["session_id"] == "test-session"
        assert bundle["sources_queried"] == ["gti", "otx"]
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
            sources_queried=["gti"],
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
                {
                    "challenge_id": 0,
                    "response": "Accepted",
                    "adjustment": "Reduced to 'roughly even chance'",
                }
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

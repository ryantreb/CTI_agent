"""Tests for inter-agent data schemas."""

import pytest
from lib.team_data import (
    create_assessment_package,
    create_collection_bundle,
    create_enriched_ioc,
    create_key_judgment,
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

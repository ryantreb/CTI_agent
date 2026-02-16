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

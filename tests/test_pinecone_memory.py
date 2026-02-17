"""Tests for Pinecone vector memory integration.

Tests record schema construction and query formatting.
Actual Pinecone calls are mocked — live integration tested via demo mode.
"""

from lib.pinecone_memory import (
    PINECONE_INDEX,
    build_intel_record,
    build_actor_record,
    build_search_query,
    format_search_results,
)


class TestBuildIntelRecord:
    def test_creates_record_from_report(self):
        record = build_intel_record(
            report_guid="rpt-001",
            summary="APT29 targets government agencies via supply chain compromise",
            report_type="tactical",
            threat_actors=["APT29"],
            ttps=["T1195.002", "T1059.001"],
            ioc_types=["ip", "domain", "hash"],
            confidence=0.85,
            campaign="SolarWinds",
        )
        assert record["_id"] == "report-rpt-001"
        assert "APT29" in record["text"]
        assert record["report_type"] == "tactical"
        assert record["confidence"] == 0.85
        assert "T1195.002" in record["ttps"]

    def test_minimal_record(self):
        record = build_intel_record(
            report_guid="rpt-002",
            summary="Unknown actor phishing campaign",
        )
        assert record["_id"] == "report-rpt-002"
        assert record["threat_actors"] == []
        assert record["ttps"] == []


class TestBuildActorRecord:
    def test_creates_record_from_profile(self):
        profile = {
            "actor_id": "APT29",
            "aliases": ["Cozy Bear"],
            "motivation": "espionage",
            "nation_state": "Russia",
            "known_ttps": [{"technique": "T1566.001"}],
            "targeting": {"sectors": ["government"], "geographies": ["US"]},
        }
        record = build_actor_record(profile)
        assert record["_id"] == "actor-APT29"
        assert "Cozy Bear" in record["text"]
        assert "espionage" in record["text"]


class TestBuildSearchQuery:
    def test_ttp_search(self):
        query = build_search_query(
            query_text="campaigns using T1566 spearphishing",
            top_k=5,
        )
        assert query["query"] == "campaigns using T1566 spearphishing"
        assert query["top_k"] == 5
        assert query["index"] == PINECONE_INDEX

    def test_actor_search_with_filter(self):
        query = build_search_query(
            query_text="APT29 infrastructure",
            top_k=10,
            filter_by={"threat_actors": "APT29"},
        )
        assert query["filter"] == {"threat_actors": "APT29"}

    def test_default_top_k(self):
        query = build_search_query(query_text="test")
        assert query["top_k"] == 5


class TestFormatSearchResults:
    def test_formats_results(self):
        raw_results = [
            {
                "_id": "report-rpt-001",
                "_score": 0.92,
                "text": "APT29 campaign targeting government",
                "report_type": "tactical",
                "date": "2026-02-16",
            },
            {
                "_id": "report-rpt-002",
                "_score": 0.78,
                "text": "Supply chain compromise analysis",
                "report_type": "strategic",
                "date": "2026-02-10",
            },
        ]
        formatted = format_search_results(raw_results)
        assert len(formatted) == 2
        assert formatted[0]["relevance_score"] == 0.92
        assert formatted[0]["id"] == "report-rpt-001"

    def test_empty_results(self):
        assert format_search_results([]) == []

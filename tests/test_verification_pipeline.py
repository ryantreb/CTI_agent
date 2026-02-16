"""Tests for verification pipeline."""

from lib.verification_pipeline import (
    aggregate_verification_results,
    classify_claim_for_verification,
    detect_hallucination_patterns,
    extract_claims_from_assessment,
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
            {
                "claim_id": "C1",
                "verification_status": "VERIFIED_HIGH",
                "confidence_score": 0.95,
            },
            {
                "claim_id": "C2",
                "verification_status": "VERIFIED_MEDIUM",
                "confidence_score": 0.75,
            },
        ]
        summary = aggregate_verification_results(results)
        assert summary["total"] == 2
        assert summary["verified_high"] == 1
        assert summary["verified_medium"] == 1
        assert summary["pass_rate"] == 1.0

    def test_aggregate_with_refuted(self):
        results = [
            {
                "claim_id": "C1",
                "verification_status": "VERIFIED_HIGH",
                "confidence_score": 0.95,
            },
            {
                "claim_id": "C2",
                "verification_status": "REFUTED",
                "confidence_score": 0.0,
            },
        ]
        summary = aggregate_verification_results(results)
        assert summary["refuted"] == 1
        assert summary["pass_rate"] == 0.5


class TestHallucinationDetection:
    """Detect patterns suggesting fabricated claims."""

    def test_detects_no_source_pattern(self):
        claims = [
            {
                "claim_id": "C1",
                "sources_checked": [],
                "verification_status": "UNVERIFIED",
            },
        ]
        flags = detect_hallucination_patterns(claims)
        assert len(flags) >= 1
        assert "C1" in flags[0]

    def test_detects_all_refuted_pattern(self):
        claims = [
            {
                "claim_id": "C1",
                "sources_checked": ["gti"],
                "verification_status": "REFUTED",
            },
            {
                "claim_id": "C2",
                "sources_checked": ["gti"],
                "verification_status": "REFUTED",
            },
            {
                "claim_id": "C3",
                "sources_checked": ["gti"],
                "verification_status": "REFUTED",
            },
        ]
        flags = detect_hallucination_patterns(claims)
        assert any("high refutation rate" in f.lower() for f in flags)

    def test_no_flags_when_all_verified(self):
        claims = [
            {
                "claim_id": "C1",
                "sources_checked": ["gti"],
                "verification_status": "VERIFIED_HIGH",
            },
        ]
        flags = detect_hallucination_patterns(claims)
        assert len(flags) == 0

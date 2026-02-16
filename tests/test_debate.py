"""Tests for Devil's Advocate debate engine."""

from lib.debate import (
    MAX_DEBATE_ROUNDS,
    build_alternative_analysis_section,
    check_consensus,
    generate_challenge_types,
    should_challenge,
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

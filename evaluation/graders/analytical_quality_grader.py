#!/usr/bin/env python3
"""
Analytical Quality Grader (LLM-as-Judge)
Assesses reasoning quality, confidence calibration, and analytical rigor.
Pass Threshold: 0.75

This grader uses an LLM to evaluate outputs against a rubric.
"""

from typing import Tuple, Optional
import json

# Evaluation rubric for LLM judge
EVALUATION_RUBRIC = """
You are an expert intelligence analyst evaluator assessing the quality of threat intelligence analysis.

Evaluate the provided analysis against this rubric:

## Scoring Criteria (0.0 to 1.0)

### 1.0 - Exemplary
- Confidence levels properly calibrated using probability language
- Clear, numbered key judgments with evidence basis
- All claims cite sources or evidence
- Assumptions explicitly stated
- Intelligence gaps acknowledged
- Logical reasoning chain is transparent
- No unsupported assertions

### 0.75 - Good  
- Most elements present
- Minor gaps in reasoning chain
- Confidence language used but occasionally imprecise
- Most claims supported by evidence
- Some assumptions may be implicit

### 0.50 - Adequate
- Basic analytical structure present
- Assumptions unstated or unclear
- Confidence not consistently calibrated
- Some claims lack supporting evidence
- Reasoning chain has gaps

### 0.25 - Poor
- Missing key sections
- Multiple unsupported claims
- No confidence calibration
- Reasoning unclear or circular
- Assumptions not examined

### 0.0 - Unacceptable
- Contains fabrications or contradictions
- Completely off-topic
- No analytical structure
- Claims directly contradict evidence
- Harmful misinformation

## Evaluation Focus Areas

1. **Confidence Calibration**: Does the analysis use proper probability language?
   - Good: "We assess with moderate confidence...", "It is likely that..."
   - Bad: "We believe...", "Probably...", uncalibrated certainty

2. **Evidence Support**: Are claims backed by cited evidence?
   - Good: "Based on GTI analysis showing 45/70 AV detections..."
   - Bad: "The malware is sophisticated" (no evidence)

3. **Assumption Transparency**: Are key assumptions stated?
   - Good: "This assessment assumes the malware attribution is accurate"
   - Bad: Hidden assumptions that could invalidate conclusions

4. **Gap Acknowledgment**: Does it recognize what is NOT known?
   - Good: "We lack visibility into adversary intent"
   - Bad: Overconfident claims without acknowledging limitations

5. **Logical Coherence**: Does the reasoning flow logically?
   - Good: Evidence → Analysis → Judgment with clear links
   - Bad: Conclusions that don't follow from presented evidence

## Response Format

Return a JSON object with:
{
  "score": <float 0.0-1.0>,
  "confidence_calibration": <float 0.0-1.0>,
  "evidence_support": <float 0.0-1.0>,
  "assumption_transparency": <float 0.0-1.0>,
  "gap_acknowledgment": <float 0.0-1.0>,
  "logical_coherence": <float 0.0-1.0>,
  "strengths": ["list", "of", "strengths"],
  "weaknesses": ["list", "of", "weaknesses"],
  "improvement_suggestions": ["specific", "actionable", "suggestions"],
  "rationale": "Brief explanation of overall score"
}
"""


def create_judge_prompt(output: str, context: Optional[str] = None) -> str:
    """Create the prompt for the LLM judge."""
    prompt = f"""{EVALUATION_RUBRIC}

## Analysis to Evaluate

{output}

"""
    if context:
        prompt += f"""
## Additional Context (Source Material)

{context}

"""

    prompt += """
Evaluate this analysis and return your assessment as JSON.
"""
    return prompt


def parse_judge_response(response: str) -> dict:
    """Parse the LLM judge response."""
    # Try to extract JSON from response
    try:
        # Handle markdown code blocks
        if "```json" in response:
            json_str = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            json_str = response.split("```")[1].split("```")[0]
        else:
            json_str = response

        return json.loads(json_str.strip())
    except (json.JSONDecodeError, IndexError):
        # Return default structure if parsing fails
        return {
            "score": 0.5,
            "error": "Failed to parse judge response",
            "raw_response": response[:500],
        }


def grade(
    output: str, context: Optional[str] = None, llm_client=None
) -> Tuple[float, dict]:
    """
    Grade analytical quality using LLM-as-Judge.

    Args:
        output: Generated report/analysis output
        context: Optional source material for comparison
        llm_client: LLM client for evaluation (if None, returns placeholder)

    Returns:
        Tuple of (score, details_dict)
    """
    # If no LLM client provided, use heuristic fallback
    if llm_client is None:
        return _heuristic_grade(output)

    # Create judge prompt
    prompt = create_judge_prompt(output, context)

    # Call LLM (implementation depends on available client)
    # This is a placeholder - actual implementation would use the client
    try:
        response = llm_client.evaluate(prompt)
        results = parse_judge_response(response)
        score = results.get("score", 0.5)
        return score, results
    except Exception as e:
        return 0.5, {"error": str(e), "fallback": True}


def _heuristic_grade(output: str) -> Tuple[float, dict]:
    """
    Fallback heuristic grading when LLM not available.
    Checks for presence of quality indicators.
    """
    import re

    scores = {}

    # Check confidence calibration
    confidence_patterns = [
        r"(?i)(?:almost\s+certain|highly\s+likely|likely|unlikely|remote\s+possibility)",
        r"(?i)(?:high|medium|low)\s+confidence",
        r"(?i)we\s+assess\s+(?:with|that)",
        r"(?i)\b(?:probably|possibly)\b",  # Less preferred but still calibration
    ]
    confidence_matches = sum(1 for p in confidence_patterns if re.search(p, output))
    scores["confidence_calibration"] = min(1.0, confidence_matches / 3)

    # Check evidence support (look for citations/references)
    evidence_patterns = [
        r"(?i)based\s+on",
        r"(?i)according\s+to",
        r"(?i)source[s]?:",
        r"(?i)reference[s]?:",
        r"(?i)(?:gti|virustotal|otx)\s+(?:analysis|report)",
        r"\[\d+\]",  # Numbered citations
    ]
    evidence_matches = sum(1 for p in evidence_patterns if re.search(p, output))
    scores["evidence_support"] = min(1.0, evidence_matches / 3)

    # Check assumption transparency
    assumption_patterns = [
        r"(?i)assumption[s]?",
        r"(?i)we\s+assume",
        r"(?i)this\s+(?:analysis|assessment)\s+assumes",
        r"(?i)key\s+assumption",
    ]
    assumption_matches = sum(1 for p in assumption_patterns if re.search(p, output))
    scores["assumption_transparency"] = min(1.0, assumption_matches / 2)

    # Check gap acknowledgment
    gap_patterns = [
        r"(?i)(?:intelligence|information|data)\s+gap",
        r"(?i)we\s+(?:do\s+not|don\'t|cannot)\s+know",
        r"(?i)(?:unknown|unclear|uncertain)",
        r"(?i)limitation[s]?",
        r"(?i)lack\s+(?:of\s+)?visibility",
    ]
    gap_matches = sum(1 for p in gap_patterns if re.search(p, output))
    scores["gap_acknowledgment"] = min(1.0, gap_matches / 2)

    # Check logical coherence (presence of structure)
    structure_patterns = [
        r"##?\s+",  # Headers
        r"\d+\.\s+",  # Numbered lists
        r"(?i)(?:therefore|thus|consequently|as\s+a\s+result)",
        r"(?i)(?:because|since|given\s+that)",
    ]
    structure_matches = sum(1 for p in structure_patterns if re.search(p, output))
    scores["logical_coherence"] = min(1.0, structure_matches / 3)

    # Calculate overall score (weighted average)
    weights = {
        "confidence_calibration": 0.25,
        "evidence_support": 0.25,
        "assumption_transparency": 0.20,
        "gap_acknowledgment": 0.15,
        "logical_coherence": 0.15,
    }

    overall_score = sum(scores[k] * weights[k] for k in weights)

    return overall_score, {
        "score": overall_score,
        "subscores": scores,
        "method": "heuristic",
        "passed": overall_score >= 0.75,
    }


def passes(score: float, threshold: float = 0.75) -> bool:
    """Check if score meets threshold."""
    return score >= threshold


if __name__ == "__main__":
    # Test with heuristic fallback
    test_output = """
    ## Executive Summary
    We assess with moderate confidence that APT29 is responsible for this intrusion.
    
    ## Key Judgments
    1. The threat actor is likely APT29 based on TTP overlap with known campaigns.
    2. The campaign is almost certainly focused on espionage objectives.
    
    ## Analysis
    Based on GTI analysis showing 45/70 AV detections, the malware exhibits 
    characteristics consistent with SUNBURST. According to CISA advisory AA21-116A,
    this malware family is attributed to APT29.
    
    ## Assumptions
    - This assessment assumes the malware attribution to APT29 is accurate
    - We assume the targeting information is complete
    
    ## Intelligence Gaps
    - We lack visibility into adversary communications
    - Cannot confirm ultimate objectives
    """

    score, details = _heuristic_grade(test_output)
    print(f"Score: {score:.2f}")
    print(f"Passed: {passes(score)}")
    print(f"Subscores: {json.dumps(details.get('subscores', {}), indent=2)}")

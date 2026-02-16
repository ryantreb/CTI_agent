#!/usr/bin/env python3
"""
Evaluation Runner
Orchestrates all graders and manages evaluation workflow.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import graders
from graders import (
    ttp_coverage_grader,
    ioc_fidelity_grader,
    framework_compliance_grader,
    analytical_quality_grader
)


# Thresholds for each grader
THRESHOLDS = {
    'ttp_coverage': 0.80,
    'ioc_fidelity': 0.90,
    'framework_compliance': 0.85,
    'analytical_quality': 0.75
}

# Overall pass threshold
AGGREGATE_THRESHOLD = 0.80


class EvaluationResult:
    """Container for evaluation results."""
    
    def __init__(self, skill: str, version: int):
        self.skill = skill
        self.version = version
        self.timestamp = datetime.utcnow().isoformat()
        self.scores: Dict[str, float] = {}
        self.details: Dict[str, dict] = {}
        self.aggregate_score: float = 0.0
        self.passed: bool = False
        self.failed_graders: List[str] = []
    
    def to_dict(self) -> dict:
        return {
            'skill': self.skill,
            'version': self.version,
            'timestamp': self.timestamp,
            'scores': self.scores,
            'aggregate_score': self.aggregate_score,
            'passed': self.passed,
            'failed_graders': self.failed_graders,
            'details': self.details
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def run_evaluation(
    source: str,
    output: str,
    skill: str,
    version: int = 0,
    llm_client=None
) -> EvaluationResult:
    """
    Run all graders on an output.
    
    Args:
        source: Original source material
        output: Generated output to evaluate
        skill: Name of skill being evaluated
        version: Current version number
        llm_client: Optional LLM client for analytical quality grader
        
    Returns:
        EvaluationResult with all scores and details
    """
    result = EvaluationResult(skill, version)
    
    # Run TTP Coverage Grader
    score, details = ttp_coverage_grader.grade(source, output)
    result.scores['ttp_coverage'] = score
    result.details['ttp_coverage'] = details
    if score < THRESHOLDS['ttp_coverage']:
        result.failed_graders.append('ttp_coverage')
    
    # Run IOC Fidelity Grader
    score, details = ioc_fidelity_grader.grade(source, output)
    result.scores['ioc_fidelity'] = score
    result.details['ioc_fidelity'] = details
    if score < THRESHOLDS['ioc_fidelity']:
        result.failed_graders.append('ioc_fidelity')
    
    # Run Framework Compliance Grader
    score, details = framework_compliance_grader.grade(output)
    result.scores['framework_compliance'] = score
    result.details['framework_compliance'] = details
    if score < THRESHOLDS['framework_compliance']:
        result.failed_graders.append('framework_compliance')
    
    # Run Analytical Quality Grader
    score, details = analytical_quality_grader.grade(output, source, llm_client)
    result.scores['analytical_quality'] = score
    result.details['analytical_quality'] = details
    if score < THRESHOLDS['analytical_quality']:
        result.failed_graders.append('analytical_quality')
    
    # Calculate aggregate score
    result.aggregate_score = sum(result.scores.values()) / len(result.scores)
    result.passed = result.aggregate_score >= AGGREGATE_THRESHOLD and len(result.failed_graders) == 0
    
    return result


def log_evaluation(result: EvaluationResult, log_dir: Path) -> None:
    """Append evaluation result to log file."""
    log_file = log_dir / 'eval_history.jsonl'
    log_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(log_file, 'a') as f:
        f.write(result.to_json() + '\n')


def get_failure_feedback(result: EvaluationResult) -> str:
    """Generate actionable feedback from failed graders."""
    feedback_parts = []
    
    for grader in result.failed_graders:
        score = result.scores[grader]
        threshold = THRESHOLDS[grader]
        details = result.details.get(grader, {})
        
        if grader == 'ttp_coverage':
            missing = details.get('missing', [])
            feedback_parts.append(
                f"TTP Coverage failed ({score:.2f} < {threshold}). "
                f"Missing TTPs: {', '.join(missing[:5])}"
            )
        
        elif grader == 'ioc_fidelity':
            if details.get('fabricated'):
                feedback_parts.append(
                    f"IOC Fidelity CRITICAL FAILURE - Fabricated IOCs detected: "
                    f"{', '.join(details['fabricated'][:3])}"
                )
            else:
                missing = details.get('missing', [])
                feedback_parts.append(
                    f"IOC Fidelity failed ({score:.2f} < {threshold}). "
                    f"Missing IOCs: {len(missing)}"
                )
        
        elif grader == 'framework_compliance':
            missing = details.get('missing_required', [])
            feedback_parts.append(
                f"Framework Compliance failed ({score:.2f} < {threshold}). "
                f"Missing sections: {', '.join(missing)}"
            )
        
        elif grader == 'analytical_quality':
            subscores = details.get('subscores', {})
            weak_areas = [k for k, v in subscores.items() if v < 0.6]
            feedback_parts.append(
                f"Analytical Quality failed ({score:.2f} < {threshold}). "
                f"Weak areas: {', '.join(weak_areas)}"
            )
    
    return '\n'.join(feedback_parts) if feedback_parts else "All graders passed."


def should_trigger_optimization(result: EvaluationResult) -> bool:
    """Determine if optimization should be triggered."""
    # Trigger if aggregate failed OR any critical grader failed badly
    if not result.passed:
        return True
    
    # Trigger if IOC fidelity shows fabrication (score = 0)
    if result.scores.get('ioc_fidelity', 1.0) == 0.0:
        return True
    
    return False


def check_for_patterns(log_dir: Path, skill: str, lookback: int = 5) -> Optional[str]:
    """
    Check evaluation history for failure patterns.
    
    Returns pattern description if detected, None otherwise.
    """
    log_file = log_dir / 'eval_history.jsonl'
    if not log_file.exists():
        return None
    
    # Read recent evaluations for this skill
    recent_evals = []
    with open(log_file, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                if entry.get('skill') == skill:
                    recent_evals.append(entry)
            except json.JSONDecodeError:
                continue
    
    # Get last N evaluations
    recent_evals = recent_evals[-lookback:]
    
    if len(recent_evals) < 3:
        return None
    
    # Check for repeating failures
    failure_counts: Dict[str, int] = {}
    for eval_entry in recent_evals:
        for grader in eval_entry.get('failed_graders', []):
            failure_counts[grader] = failure_counts.get(grader, 0) + 1
    
    # Pattern: Same grader failing 3+ times
    for grader, count in failure_counts.items():
        if count >= 3:
            return f"Repeated failure pattern: {grader} has failed {count}/{len(recent_evals)} recent evaluations"
    
    # Pattern: Overall declining scores
    scores = [e.get('aggregate_score', 0) for e in recent_evals]
    if len(scores) >= 3 and all(scores[i] > scores[i+1] for i in range(len(scores)-1)):
        return f"Model drift detected: Scores declining over {len(scores)} sessions"
    
    return None


if __name__ == "__main__":
    # Test evaluation
    test_source = """
    APT29 used T1566.001 for initial access via spearphishing.
    C2 server: 185.234.72.15
    Malware hash: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
    """
    
    test_output = """
    ## Executive Summary
    We assess with moderate confidence that APT29 conducted this campaign.
    
    ## Key Judgments
    1. APT29 is likely responsible based on TTP analysis.
    
    ## ATT&CK Mapping
    | Technique | Name |
    |-----------|------|
    | T1566.001 | Spearphishing Attachment |
    
    ## Indicators of Compromise
    | Type | Value |
    |------|-------|
    | IP | 185[.]234[.]72[.]15 |
    | SHA256 | a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd |
    
    ## Defensive Recommendations
    1. Block identified C2 infrastructure
    2. Enable email attachment scanning
    3. Deploy YARA rules for malware detection
    
    ## Assumptions
    - Attribution based on known APT29 TTPs
    
    ## Intelligence Gaps
    - Cannot confirm adversary objectives
    
    ## Sources
    - GTI file analysis
    - CISA advisory
    """
    
    result = run_evaluation(test_source, test_output, 'generate-report', version=1)
    
    print(f"Aggregate Score: {result.aggregate_score:.2f}")
    print(f"Passed: {result.passed}")
    print(f"Failed Graders: {result.failed_graders}")
    print(f"\nScores:")
    for grader, score in result.scores.items():
        threshold = THRESHOLDS[grader]
        status = "✓" if score >= threshold else "✗"
        print(f"  {status} {grader}: {score:.2f} (threshold: {threshold})")
    
    if not result.passed:
        print(f"\nFeedback:\n{get_failure_feedback(result)}")

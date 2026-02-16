#!/usr/bin/env python3
"""
TTP Coverage Grader
Measures what percentage of MITRE ATT&CK technique IDs from source appear in output.
Pass Threshold: 0.80
"""

import re
from typing import Tuple

# MITRE ATT&CK technique pattern: T#### or T####.###
TTP_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')


def extract_ttps(text: str) -> set:
    """Extract all unique TTP IDs from text."""
    return set(TTP_PATTERN.findall(text))


def grade(source: str, output: str) -> Tuple[float, dict]:
    """
    Grade TTP coverage.
    
    Args:
        source: Original intelligence source text
        output: Generated report/analysis output
        
    Returns:
        Tuple of (score, details_dict)
    """
    source_ttps = extract_ttps(source)
    output_ttps = extract_ttps(output)
    
    # If no TTPs in source, nothing to cover
    if not source_ttps:
        return 1.0, {
            "source_ttps": [],
            "output_ttps": list(output_ttps),
            "covered": [],
            "missing": [],
            "note": "No TTPs in source to cover"
        }
    
    covered = source_ttps & output_ttps
    missing = source_ttps - output_ttps
    extra = output_ttps - source_ttps  # TTPs in output but not source (may be valid enrichment)
    
    coverage_score = len(covered) / len(source_ttps)
    
    return coverage_score, {
        "source_ttps": sorted(list(source_ttps)),
        "output_ttps": sorted(list(output_ttps)),
        "covered": sorted(list(covered)),
        "missing": sorted(list(missing)),
        "extra": sorted(list(extra)),
        "coverage_ratio": f"{len(covered)}/{len(source_ttps)}"
    }


def passes(score: float, threshold: float = 0.80) -> bool:
    """Check if score meets threshold."""
    return score >= threshold


if __name__ == "__main__":
    # Test example
    test_source = """
    The threat actor used T1566.001 (Spearphishing Attachment) for initial access,
    followed by T1059.001 (PowerShell) for execution. Persistence was achieved via
    T1547.001 (Registry Run Keys). C2 communications used T1071.001 (Web Protocols).
    """
    
    test_output = """
    ## ATT&CK Mapping
    | Technique | Description |
    |-----------|-------------|
    | T1566.001 | Spearphishing Attachment |
    | T1059.001 | PowerShell Execution |
    | T1547.001 | Registry Run Keys |
    """
    
    score, details = grade(test_source, test_output)
    print(f"Score: {score:.2f}")
    print(f"Passed: {passes(score)}")
    print(f"Missing TTPs: {details['missing']}")

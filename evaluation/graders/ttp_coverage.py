#!/usr/bin/env python3
"""
TTP Coverage Grader
Measures what percentage of MITRE ATT&CK TTPs in source appear in output.

Pass threshold: 0.80
"""

import re
import sys
import json
from typing import Set


# MITRE ATT&CK TTP pattern: T#### or T####.###
TTP_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?')


def extract_ttps(text: str) -> Set[str]:
    """Extract all TTP IDs from text."""
    return set(TTP_PATTERN.findall(text))


def grade_ttp_coverage(source: str, output: str) -> float:
    """
    Calculate TTP coverage score.
    
    Args:
        source: Original intelligence containing TTPs
        output: Agent's analysis or report
        
    Returns:
        Score between 0.0 and 1.0
    """
    source_ttps = extract_ttps(source)
    output_ttps = extract_ttps(output)
    
    # No TTPs to cover = automatic pass
    if not source_ttps:
        return 1.0
    
    # Calculate intersection coverage
    covered = source_ttps & output_ttps
    coverage = len(covered) / len(source_ttps)
    
    return round(coverage, 2)


def main():
    """CLI interface for grader."""
    if len(sys.argv) < 3:
        print("Usage: ttp_coverage.py <source_file> <output_file>")
        print("       Returns JSON: {score: float, details: dict}")
        sys.exit(1)
    
    source_path = sys.argv[1]
    output_path = sys.argv[2]
    
    with open(source_path, 'r') as f:
        source = f.read()
    
    with open(output_path, 'r') as f:
        output = f.read()
    
    source_ttps = extract_ttps(source)
    output_ttps = extract_ttps(output)
    score = grade_ttp_coverage(source, output)
    
    result = {
        "grader": "ttp_coverage",
        "score": score,
        "pass_threshold": 0.80,
        "passed": score >= 0.80,
        "details": {
            "source_ttps": sorted(list(source_ttps)),
            "output_ttps": sorted(list(output_ttps)),
            "covered": sorted(list(source_ttps & output_ttps)),
            "missing": sorted(list(source_ttps - output_ttps))
        }
    }
    
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Framework Compliance Grader
Checks that required intelligence report sections are present.

Pass threshold: 0.85
"""

import re
import sys
import json
from typing import List, Tuple


# Required sections with regex patterns
REQUIRED_SECTIONS: List[Tuple[str, str]] = [
    (r'(?i)(executive\s+summary|summary|bluf)', 'Executive Summary'),
    (r'(?i)(key\s+(highlights|judgments|findings|assessments))', 'Key Judgments'),
    (r'(?i)((mitre\s+)?att&ck|ttp\s+mapping|technique.*id)', 'ATT&CK Mapping'),
    (r'(?i)(indicators?\s+of\s+compromise|iocs?|network\s+indicators?|file\s+indicators?)', 'IOCs'),
    (r'(?i)(defensive\s+(recommendations?|actions?)|mitigations?|countermeasures?)', 'Recommendations'),
    (r'(?i)((key\s+)?assumptions?|limitations?|caveats?)', 'Assumptions'),
    (r'(?i)((intelligence\s+)?gaps?|unknown|missing\s+information)', 'Intelligence Gaps'),
    (r'(?i)(confidence|likely|unlikely|assess)', 'Confidence Language'),
]


def check_section(pattern: str, text: str) -> bool:
    """Check if section pattern exists in text."""
    return bool(re.search(pattern, text))


def grade_framework_compliance(output: str) -> float:
    """
    Calculate framework compliance score.
    
    Args:
        output: Agent's report
        
    Returns:
        Score between 0.0 and 1.0 based on section coverage
    """
    present = 0
    
    for pattern, _ in REQUIRED_SECTIONS:
        if check_section(pattern, output):
            present += 1
    
    return round(present / len(REQUIRED_SECTIONS), 2)


def get_section_details(output: str) -> dict:
    """Get detailed breakdown of section presence."""
    details = {
        "present": [],
        "missing": [],
        "total_required": len(REQUIRED_SECTIONS)
    }
    
    for pattern, section_name in REQUIRED_SECTIONS:
        if check_section(pattern, output):
            details["present"].append(section_name)
        else:
            details["missing"].append(section_name)
    
    return details


def main():
    """CLI interface for grader."""
    if len(sys.argv) < 2:
        print("Usage: framework_compliance.py <output_file>")
        print("       Returns JSON: {score: float, details: dict}")
        sys.exit(1)
    
    output_path = sys.argv[1]
    
    with open(output_path, 'r') as f:
        output = f.read()
    
    score = grade_framework_compliance(output)
    details = get_section_details(output)
    
    result = {
        "grader": "framework_compliance",
        "score": score,
        "pass_threshold": 0.85,
        "passed": score >= 0.85,
        "details": details
    }
    
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

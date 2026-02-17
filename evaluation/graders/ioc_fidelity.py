#!/usr/bin/env python3
"""
IOC Fidelity Grader
Verifies IOCs in output are accurate and not hallucinated.

Pass threshold: 0.90
CRITICAL: Returns 0.0 if ANY hallucinated IOCs detected.
"""

import re
import sys
import json
from typing import Set, Dict


# IOC extraction patterns
IOC_PATTERNS: Dict[str, re.Pattern] = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
    "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
}

# Common false positives to filter
FALSE_POSITIVE_DOMAINS = {
    "example.com",
    "test.com",
    "localhost",
    "microsoft.com",
    "google.com",
    "github.com",
    "virustotal.com",
    "abuse.ch",
    "malwarebazaar.abuse.ch",
}

FALSE_POSITIVE_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "192.168.0.1",
    "10.0.0.1",
    "172.16.0.1",
}


def extract_iocs(text: str) -> Dict[str, Set[str]]:
    """Extract all IOCs from text, categorized by type."""
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = set(pattern.findall(text))

        # Filter false positives
        if ioc_type == "domain":
            matches -= FALSE_POSITIVE_DOMAINS
        elif ioc_type == "ipv4":
            matches -= FALSE_POSITIVE_IPS

        if matches:
            iocs[ioc_type] = matches

    return iocs


def flatten_iocs(iocs: Dict[str, Set[str]]) -> Set[str]:
    """Flatten IOC dict to single set."""
    result = set()
    for ioc_set in iocs.values():
        result.update(ioc_set)
    return result


def grade_ioc_fidelity(source: str, output: str) -> float:
    """
    Calculate IOC fidelity score.

    Args:
        source: Original data containing ground truth IOCs
        output: Agent's output

    Returns:
        Score between 0.0 and 1.0
        Returns 0.0 if ANY hallucinated IOCs detected
    """
    source_iocs = flatten_iocs(extract_iocs(source))
    output_iocs = flatten_iocs(extract_iocs(output))

    # CRITICAL: Check for hallucinated IOCs
    hallucinated = output_iocs - source_iocs
    if hallucinated:
        # Severe penalty for fabrication - this is unacceptable
        return 0.0

    # No IOCs to cover = automatic pass
    if not source_iocs:
        return 1.0

    # Calculate coverage
    covered = source_iocs & output_iocs
    coverage = len(covered) / len(source_iocs)

    return round(coverage, 2)


def main():
    """CLI interface for grader."""
    if len(sys.argv) < 3:
        print("Usage: ioc_fidelity.py <source_file> <output_file>")
        print("       Returns JSON: {score: float, details: dict}")
        sys.exit(1)

    source_path = sys.argv[1]
    output_path = sys.argv[2]

    with open(source_path, "r") as f:
        source = f.read()

    with open(output_path, "r") as f:
        output = f.read()

    source_iocs_by_type = extract_iocs(source)
    output_iocs_by_type = extract_iocs(output)

    source_iocs = flatten_iocs(source_iocs_by_type)
    output_iocs = flatten_iocs(output_iocs_by_type)

    hallucinated = output_iocs - source_iocs
    score = grade_ioc_fidelity(source, output)

    result = {
        "grader": "ioc_fidelity",
        "score": score,
        "pass_threshold": 0.90,
        "passed": score >= 0.90,
        "hallucination_detected": len(hallucinated) > 0,
        "details": {
            "source_iocs_count": len(source_iocs),
            "output_iocs_count": len(output_iocs),
            "covered_count": len(source_iocs & output_iocs),
            "hallucinated": sorted(list(hallucinated))[:10],  # Limit for readability
            "by_type": {
                ioc_type: {
                    "source": len(source_iocs_by_type.get(ioc_type, set())),
                    "output": len(output_iocs_by_type.get(ioc_type, set())),
                }
                for ioc_type in IOC_PATTERNS.keys()
            },
        },
    }

    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
IOC Fidelity Grader
Verifies IOCs in output are valid format and present in source (no hallucination).
Pass Threshold: 0.90
"""

import re
from typing import Tuple, Set, Dict

# IOC patterns
IOC_PATTERNS = {
    'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'ipv4_defanged': re.compile(r'\b(?:\d{1,3}\[\.\]){3}\d{1,3}\b'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    'domain_defanged': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\[\.\])+[a-zA-Z]{2,}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    'url_defanged': re.compile(r'hxxps?://[^\s<>"{}|\\^`\[\]]+'),
}

# Common false positives to exclude
FALSE_POSITIVE_PATTERNS = [
    r'^127\.0\.0\.1$',           # Localhost
    r'^192\.168\.\d+\.\d+$',     # Private IP (example)
    r'^10\.\d+\.\d+\.\d+$',      # Private IP
    r'^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$',  # Private IP
    r'^0{32}$',                  # Null MD5
    r'^0{40}$',                  # Null SHA1
    r'^0{64}$',                  # Null SHA256
    r'example\.com$',            # Example domain
    r'test\.com$',               # Test domain
]


def normalize_ioc(ioc: str, ioc_type: str) -> str:
    """Normalize IOC by removing defanging."""
    normalized = ioc.lower()
    normalized = normalized.replace('[.]', '.')
    normalized = normalized.replace('hxxp', 'http')
    return normalized


def extract_iocs(text: str) -> Dict[str, Set[str]]:
    """Extract all IOCs from text, normalized."""
    iocs = {ioc_type: set() for ioc_type in ['ip', 'domain', 'hash', 'url']}
    
    # Extract IPs
    for pattern in [IOC_PATTERNS['ipv4'], IOC_PATTERNS['ipv4_defanged']]:
        for match in pattern.findall(text):
            normalized = normalize_ioc(match, 'ip')
            # Filter false positives
            if not any(re.match(fp, normalized) for fp in FALSE_POSITIVE_PATTERNS[:4]):
                iocs['ip'].add(normalized)
    
    # Extract domains
    for pattern in [IOC_PATTERNS['domain'], IOC_PATTERNS['domain_defanged']]:
        for match in pattern.findall(text):
            normalized = normalize_ioc(match, 'domain')
            if not any(re.search(fp, normalized) for fp in FALSE_POSITIVE_PATTERNS[7:]):
                iocs['domain'].add(normalized)
    
    # Extract hashes
    for hash_type in ['sha256', 'sha1', 'md5']:
        for match in IOC_PATTERNS[hash_type].findall(text):
            normalized = match.lower()
            if not any(re.match(fp, normalized) for fp in FALSE_POSITIVE_PATTERNS[4:7]):
                iocs['hash'].add(normalized)
    
    # Extract URLs
    for pattern in [IOC_PATTERNS['url'], IOC_PATTERNS['url_defanged']]:
        for match in pattern.findall(text):
            normalized = normalize_ioc(match, 'url')
            iocs['url'].add(normalized)
    
    return iocs


def grade(source: str, output: str) -> Tuple[float, dict]:
    """
    Grade IOC fidelity.
    
    Args:
        source: Original intelligence source text
        output: Generated report/analysis output
        
    Returns:
        Tuple of (score, details_dict)
    """
    source_iocs = extract_iocs(source)
    output_iocs = extract_iocs(output)
    
    all_source = set()
    all_output = set()
    
    for ioc_type in source_iocs:
        all_source.update(source_iocs[ioc_type])
        all_output.update(output_iocs[ioc_type])
    
    # Check for fabricated IOCs (hallucination)
    fabricated = all_output - all_source
    
    # CRITICAL: Any fabricated IOC is a serious error
    if fabricated:
        return 0.0, {
            "source_iocs": {k: list(v) for k, v in source_iocs.items()},
            "output_iocs": {k: list(v) for k, v in output_iocs.items()},
            "fabricated": list(fabricated),
            "error": "HALLUCINATION DETECTED - Output contains IOCs not in source",
            "passed": False
        }
    
    # If no IOCs in source, check output doesn't fabricate any
    if not all_source:
        if all_output:
            return 0.0, {
                "error": "Output contains IOCs but source has none - possible hallucination",
                "fabricated": list(all_output),
                "passed": False
            }
        return 1.0, {
            "note": "No IOCs in source or output",
            "passed": True
        }
    
    # Calculate coverage
    covered = all_source & all_output
    missing = all_source - all_output
    
    coverage_score = len(covered) / len(all_source)
    
    return coverage_score, {
        "source_ioc_count": len(all_source),
        "output_ioc_count": len(all_output),
        "covered": list(covered),
        "missing": list(missing),
        "fabricated": [],
        "coverage_ratio": f"{len(covered)}/{len(all_source)}",
        "passed": coverage_score >= 0.90
    }


def passes(score: float, threshold: float = 0.90) -> bool:
    """Check if score meets threshold."""
    return score >= threshold


if __name__ == "__main__":
    # Test example
    test_source = """
    C2 server: 185.234.72.15
    Malware hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    Domain: malicious-c2[.]com
    """
    
    test_output = """
    ## IOCs
    | Type | Value |
    |------|-------|
    | IP | 185[.]234[.]72[.]15 |
    | SHA256 | a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 |
    | Domain | malicious-c2[.]com |
    """
    
    score, details = grade(test_source, test_output)
    print(f"Score: {score:.2f}")
    print(f"Passed: {passes(score)}")
    print(f"Details: {details}")

#!/usr/bin/env python3
"""
Framework Compliance Grader
Checks that required report sections are present per intelligence standards.
Pass Threshold: 0.85
"""

import re
from typing import Tuple, List, Dict

# Required sections with regex patterns
REQUIRED_SECTIONS = {
    'executive_summary': {
        'patterns': [
            r'(?i)##?\s*executive\s+summary',
            r'(?i)##?\s*summary',
            r'(?i)##?\s*bluf',
            r'(?i)##?\s*bottom\s+line',
        ],
        'weight': 1.0,
        'description': 'Executive Summary / BLUF'
    },
    'key_judgments': {
        'patterns': [
            r'(?i)##?\s*key\s+(?:judgments?|findings?|assessments?)',
            r'(?i)##?\s*(?:main|primary)\s+(?:judgments?|findings?)',
        ],
        'weight': 1.0,
        'description': 'Key Judgments/Findings'
    },
    'attack_mapping': {
        'patterns': [
            r'(?i)##?\s*(?:mitre\s+)?att&?ck',
            r'(?i)##?\s*ttp\s+(?:mapping|analysis)',
            r'(?i)##?\s*technique\s+(?:mapping|analysis)',
            r'(?i)\|\s*T\d{4}',  # ATT&CK technique in table
        ],
        'weight': 1.0,
        'description': 'ATT&CK/TTP Mapping'
    },
    'iocs': {
        'patterns': [
            r'(?i)##?\s*indicators?\s+of\s+compromise',
            r'(?i)##?\s*iocs?',
            r'(?i)##?\s*(?:network|file|host)\s+indicators?',
        ],
        'weight': 1.0,
        'description': 'Indicators of Compromise'
    },
    'defensive_recommendations': {
        'patterns': [
            r'(?i)##?\s*(?:defensive|security)\s+recommendations?',
            r'(?i)##?\s*(?:defensive|mitigation)\s+actions?',
            r'(?i)##?\s*recommendations?',
            r'(?i)##?\s*mitigations?',
        ],
        'weight': 1.0,
        'description': 'Defensive Recommendations'
    },
    'gaps_assumptions': {
        'patterns': [
            r'(?i)##?\s*(?:gaps?|limitations?)\s*(?:and|&)?\s*assumptions?',
            r'(?i)##?\s*(?:key\s+)?assumptions?',
            r'(?i)##?\s*intelligence\s+gaps?',
            r'(?i)##?\s*(?:information|data)\s+gaps?',
        ],
        'weight': 1.0,
        'description': 'Gaps & Assumptions'
    },
    'confidence_language': {
        'patterns': [
            r'(?i)(?:almost\s+certain|highly\s+likely|likely|unlikely|highly\s+unlikely)',
            r'(?i)(?:high|medium|low)\s+confidence',
            r'(?i)we\s+assess\s+(?:with|that)',
        ],
        'weight': 0.5,  # Lower weight - can appear anywhere
        'description': 'Confidence Calibration Language'
    },
    'sources': {
        'patterns': [
            r'(?i)##?\s*sources?',
            r'(?i)##?\s*references?',
            r'(?i)##?\s*citations?',
        ],
        'weight': 0.5,
        'description': 'Sources/References'
    }
}

# Optional but valuable sections
OPTIONAL_SECTIONS = {
    'diamond_model': {
        'patterns': [
            r'(?i)##?\s*diamond\s+model',
            r'(?i)adversary.*infrastructure.*capability.*victim',
        ],
        'description': 'Diamond Model Analysis'
    },
    'kill_chain': {
        'patterns': [
            r'(?i)##?\s*(?:cyber\s+)?kill\s+chain',
            r'(?i)reconnaissance.*delivery.*exploitation',
        ],
        'description': 'Kill Chain Mapping'
    },
    'ach': {
        'patterns': [
            r'(?i)##?\s*(?:analysis\s+of\s+)?competing\s+hypothes[ei]s',
            r'(?i)##?\s*ach\s+(?:analysis|assessment)',
            r'(?i)hypothesis\s+ranking',
        ],
        'description': 'ACH Analysis'
    }
}


def check_section(text: str, patterns: List[str]) -> bool:
    """Check if any pattern matches in text."""
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False


def grade(output: str) -> Tuple[float, dict]:
    """
    Grade framework compliance.
    
    Args:
        output: Generated report/analysis output
        
    Returns:
        Tuple of (score, details_dict)
    """
    results = {
        'required_sections': {},
        'optional_sections': {},
        'missing_required': [],
        'present_optional': []
    }
    
    total_weight = 0.0
    achieved_weight = 0.0
    
    # Check required sections
    for section_id, section_info in REQUIRED_SECTIONS.items():
        present = check_section(output, section_info['patterns'])
        results['required_sections'][section_id] = {
            'present': present,
            'description': section_info['description'],
            'weight': section_info['weight']
        }
        total_weight += section_info['weight']
        if present:
            achieved_weight += section_info['weight']
        else:
            results['missing_required'].append(section_info['description'])
    
    # Check optional sections (informational only)
    for section_id, section_info in OPTIONAL_SECTIONS.items():
        present = check_section(output, section_info['patterns'])
        results['optional_sections'][section_id] = {
            'present': present,
            'description': section_info['description']
        }
        if present:
            results['present_optional'].append(section_info['description'])
    
    # Calculate score
    score = achieved_weight / total_weight if total_weight > 0 else 0.0
    
    results['score'] = score
    results['achieved_weight'] = achieved_weight
    results['total_weight'] = total_weight
    results['passed'] = score >= 0.85
    
    return score, results


def passes(score: float, threshold: float = 0.85) -> bool:
    """Check if score meets threshold."""
    return score >= threshold


def get_improvement_suggestions(results: dict) -> List[str]:
    """Generate suggestions for improving compliance."""
    suggestions = []
    
    for section in results.get('missing_required', []):
        suggestions.append(f"Add section: {section}")
    
    if 'Confidence Calibration Language' in results.get('missing_required', []):
        suggestions.append("Use ICD 203 probability language: 'likely', 'highly likely', 'almost certain', etc.")
    
    return suggestions


if __name__ == "__main__":
    # Test example
    test_output = """
    # Threat Analysis Report
    
    ## Executive Summary
    APT29 conducted a spearphishing campaign targeting government entities.
    
    ## Key Judgments
    1. We assess with high confidence that APT29 is responsible.
    2. The campaign is likely ongoing.
    
    ## ATT&CK Mapping
    | Technique | Description |
    |-----------|-------------|
    | T1566.001 | Spearphishing |
    
    ## Indicators of Compromise
    - Domain: evil.com
    - IP: 1.2.3.4
    
    ## Defensive Recommendations
    1. Block identified IOCs
    2. Enable macro blocking
    
    ## Gaps and Assumptions
    - Assumption: Attribution based on known TTPs
    - Gap: No visibility into adversary intent
    
    ## Sources
    - CISA Advisory AA21-116A
    """
    
    score, details = grade(test_output)
    print(f"Score: {score:.2f}")
    print(f"Passed: {passes(score)}")
    print(f"Missing: {details['missing_required']}")
    print(f"Optional present: {details['present_optional']}")

---
name: produce-stix-bundle
description: Transform Diamond Model analysis output into STIX 2.1 bundles. Use after diamond-model-analysis to produce machine-readable threat intelligence in OASIS STIX 2.1 format for sharing with SIEMs, TIPs, and partner organizations.
---

# Produce STIX Bundle Skill

## Purpose

Convert Diamond Model analysis into STIX 2.1 bundles for machine-to-machine intelligence sharing.

## Prerequisites

- Completed Diamond Model analysis output (from `diamond-model-analysis` skill)
- IOC enrichment data (from `enrich-iocs` skill)

## Mapping: Diamond Model → STIX 2.1

| Diamond Element | STIX 2.1 Object(s) |
|----------------|---------------------|
| Adversary | `threat-actor` SDO + `intrusion-set` SDO (if campaign identified) |
| Infrastructure | `infrastructure` SDO + `indicator` SDOs (one per IOC) |
| Capability | `malware` SDO + `attack-pattern` SDOs (from ATT&CK mapping) |
| Victim | `identity` SDO |
| Relationships | `relationship` SROs (uses, targets, indicates, attributed-to) |
| Kill Chain | `kill-chain-phase` embedded in attack-pattern SDOs |

## Indicator Pattern Syntax

Use STIX Patterning Language:

```
IP:     [ipv4-addr:value = '1.2.3.4']
Domain: [domain-name:value = 'evil.com']
Hash:   [file:hashes.'SHA-256' = 'abc123...']
URL:    [url:value = 'https://evil.com/payload']
Email:  [email-addr:value = 'phish@evil.com']
```

## Execution Protocol

```
THOUGHT: I have Diamond Model analysis output. I need to produce a STIX 2.1 bundle.

ACTION: Extract all Diamond Model elements from analysis output
OBSERVATION: Identified adversary, infrastructure, capability, victim elements

ACTION: For each Diamond element, create corresponding STIX SDOs:
  1. Adversary → threat-actor (always) + intrusion-set (if campaign)
  2. Infrastructure → infrastructure + indicator per IOC
  3. Capability → malware + attack-pattern per TTP
  4. Victim → identity

ACTION: Create STIX SROs linking objects:
  - threat-actor USES malware
  - threat-actor USES infrastructure
  - threat-actor TARGETS identity (victim)
  - indicator INDICATES infrastructure
  - malware TARGETS identity (victim)
  - attack-pattern (kill chain phases embedded)

ACTION: Assemble bundle and validate
OBSERVATION: Bundle contains N SDOs and M SROs

ACTION: Save to reports/{guid}_stix_bundle.json

CONCLUSION: STIX 2.1 bundle produced with {N} objects
```

## Confidence Mapping

Map ICD 203 confidence to STIX confidence scores (0-100):

| ICD 203 Term | STIX Score |
|-------------|-----------|
| Almost certain | 95 |
| Highly likely | 85 |
| Likely | 70 |
| Roughly even chance | 50 |
| Unlikely | 30 |
| Highly unlikely | 15 |
| Remote possibility | 5 |

## Validation

After generating the bundle:
1. Verify all object IDs follow STIX 2.1 format (`type--uuid`)
2. Verify all relationships reference valid source/target IDs
3. Verify indicator patterns use valid STIX Patterning Language
4. Cross-reference with TI Mindmap HUB MCP if available (validation, not replacement)

## Output

- **File**: `reports/{guid}_stix_bundle.json`
- **Format**: STIX 2.1 Bundle JSON
- **Log**: Record bundle creation in `logs/{date}.jsonl`

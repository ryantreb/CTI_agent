---
name: produce-attack-layers
description: Generate ATT&CK Navigator layer JSON files from Diamond Model analysis output. Use after diamond-model-analysis to produce visual technique coverage maps with confidence-based coloring for ATT&CK Navigator.
---

# Produce ATT&CK Layers Skill

## Purpose

Auto-generate ATT&CK Navigator layer files from analysis output for visual technique coverage mapping.

## Prerequisites

- Completed Diamond Model analysis (from `diamond-model-analysis` skill)
- ATT&CK technique IDs mapped in analysis output

## Layer Schema (Navigator v4.5)

Output follows ATT&CK Navigator layer format v4.5:
- `domain`: "enterprise-attack" (default), "mobile-attack", or "ics-attack"
- `techniques[]`: Array of technique entries with color, score, and metadata
- `gradient`: Maps scores 0-100 to yellow->orange->red color range

## Color Coding by Confidence

| Confidence | Color | Hex | Score |
|-----------|-------|-----|-------|
| Confirmed/observed (high) | Red | #ff6666 | 85 |
| Likely/enrichment-based (medium) | Orange | #ffaa66 | 50 |
| Possible/low confidence (low) | Yellow | #ffff66 | 25 |

## Execution Protocol

```
THOUGHT: I have Diamond Model analysis with ATT&CK technique mappings. Generate a Navigator layer.

ACTION: Extract all ATT&CK technique IDs and their confidence levels from analysis output
OBSERVATION: Found N techniques across M tactics

ACTION: For each technique:
  1. Map confidence level to color and score
  2. Include tactic for positioning
  3. Add metadata (confidence level, evidence source)
  4. Add comment describing observation

ACTION: Build layer JSON with Navigator v4.5 schema
OBSERVATION: Layer contains N technique entries

ACTION: Save to reports/{guid}_attack_layer.json

CONCLUSION: ATT&CK Navigator layer generated with {N} techniques
```

## Integration Points

- **Capa-MCP**: Capa output maps directly to ATT&CK techniques -- automatically feed results into layer
- **Diamond Model**: Kill chain phases provide tactic assignment
- **Enrichment data**: Source attribution provides confidence levels

## Output

- **File**: `reports/{guid}_attack_layer.json`
- **Format**: ATT&CK Navigator Layer JSON v4.5
- **Usage**: Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) or embed in reports

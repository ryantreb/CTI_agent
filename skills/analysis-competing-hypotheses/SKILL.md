---
name: analysis-competing-hypotheses
description: Apply Analysis of Competing Hypotheses (ACH) for attribution assessment and reducing confirmation bias. Use when multiple explanations exist for observed activity, attribution is uncertain, or high-stakes decisions require structured reasoning. Essential SAT for professional intelligence analysis.
---

# Analysis of Competing Hypotheses (ACH) Skill

## Purpose
Systematically evaluate competing explanations to reduce confirmation bias and produce calibrated attribution assessments.

## When to Use ACH

- Attribution assessment required
- Multiple plausible explanations exist
- High-stakes decision (incident response, public attribution)
- Need to document analytical reasoning for review

## Seven-Step ACH Process

### Step 1: Identify All Hypotheses

Generate ALL plausible hypotheses including:
- The obvious explanation
- Alternative explanations  
- Deception hypothesis (adversary wants us to think X)
- Null hypothesis (random/unattributed activity)

**Minimum**: 3 hypotheses per analysis

```json
{
  "hypotheses": [
    {"id": "H1", "description": "APT29 conducting espionage campaign"},
    {"id": "H2", "description": "Criminal group mimicking APT29 TTPs"},
    {"id": "H3", "description": "Unattributed actor using leaked tools"},
    {"id": "H0", "description": "Unrelated activity / false positive"}
  ]
}
```

### Step 2: List All Evidence

Enumerate ALL available evidence without pre-filtering:

| Category | Examples |
|----------|----------|
| Technical | Malware hashes, C2 domains, exploit code |
| Behavioral | TTPs, operational timing, tradecraft |
| Contextual | Victim sector, geopolitics, historical targeting |
| External | Government advisories, vendor reports |
| Negative | Expected evidence that is ABSENT |

### Step 3: Create Diagnosticity Matrix

For EACH evidence item, assess consistency with EACH hypothesis:

| Evidence | H1 (APT29) | H2 (Criminal) | H3 (Leaked) | H0 (Unrelated) |
|----------|------------|---------------|-------------|----------------|
| Known APT29 malware | CC | I | C | I |
| Supply chain vector | CC | I | N | I |
| Long dwell time | C | I | N | N |
| Financial motive | I | CC | N | N |
| Russian language strings | C | N | C | N |

**Scoring Legend:**
- **CC** = Consistent & Characteristic (+2) — Strongly supports, expected if true
- **C** = Consistent (+1) — Supports but not distinctive
- **N** = Neutral (0) — Neither supports nor refutes
- **I** = Inconsistent (-1) — Argues against
- **II** = Strongly Inconsistent (-2) — Significantly argues against

### Step 4: Refine Hypotheses

- Eliminate hypotheses with multiple **II** scores
- Merge hypotheses that cannot be distinguished by available evidence
- Add new hypotheses if evidence suggests unexplored explanations

### Step 5: Identify Diagnostic Evidence

Focus on evidence that DISTINGUISHES between hypotheses.

**High Diagnostic Value**: Evidence that is CC for one hypothesis but I for others.

**Low Diagnostic Value**: Evidence consistent with ALL hypotheses (doesn't help decide).

### Step 6: Calculate Likelihood

**CRITICAL**: Do NOT count supporting evidence (confirmation bias trap).

Instead, focus on which hypothesis has the LEAST inconsistent evidence:

```
hypothesis_score = Σ(evidence_weight × consistency_score)

Where:
  consistency_scores: CC=+2, C=+1, N=0, I=-1, II=-2
  evidence_weights: based on source reliability (0.5-1.0)
```

Rank hypotheses by score. Most likely = highest score (least refuted).

### Step 7: Document Assessment

**Required sections:**
1. Hypothesis ranking with confidence levels
2. Key diagnostic evidence (what drove the assessment)
3. Key assumptions (what we're assuming is true)
4. Information gaps (what would increase certainty)
5. Reassessment triggers (conditions that would change assessment)

## Confidence Calibration (ICD 203)

| Term | Probability | When to Use |
|------|-------------|-------------|
| Almost certain | >95% | Near-definitive; rarely appropriate |
| Highly likely | 80-95% | Strong evidence, minimal alternatives |
| Likely | 60-80% | Preponderance supports |
| Roughly even chance | 40-60% | Balanced or insufficient evidence |
| Unlikely | 20-40% | More evidence refutes |
| Highly unlikely | 5-20% | Strong evidence against |
| Remote possibility | <5% | Theoretically possible only |

## Output Schema

```json
{
  "analysis_type": "ach",
  "question": "Who is responsible for the observed intrusion?",
  "hypotheses": [
    {
      "id": "H1",
      "description": "APT29 conducting espionage",
      "score": 4.5,
      "ranking": 1,
      "inconsistencies": ["No financial motive observed"],
      "key_supporting": ["Known malware", "Targeting pattern"]
    }
  ],
  "evidence_matrix": [
    {
      "evidence": "SUNBURST malware signature",
      "source": "GTI file analysis",
      "reliability": 0.9,
      "scores": {"H1": "CC", "H2": "I", "H3": "C", "H0": "I"},
      "diagnostic_value": "high"
    }
  ],
  "key_assumptions": [
    {
      "assumption": "Malware attribution to APT29 is accurate",
      "basis": "CISA AA21-116A, multiple vendor confirmation",
      "impact_if_wrong": "Would invalidate H1 entirely"
    }
  ],
  "information_gaps": [
    {
      "gap": "No visibility into adversary communications",
      "impact": "Cannot confirm intent/motivation",
      "collection_recommendation": "Request SIGINT support if available"
    }
  ],
  "assessment": {
    "most_likely": "H1",
    "confidence": "likely",
    "confidence_numeric": 0.70,
    "analytic_line": "APT29 is the likely actor based on malware signatures and targeting pattern, though criminal mimicry cannot be ruled out."
  },
  "reassessment_triggers": [
    "Discovery of financial exfiltration would elevate H2",
    "New government attribution would increase H1 confidence",
    "Evidence of tool sharing would require new hypotheses"
  ]
}
```

## Common Pitfalls to Avoid

| Pitfall | Mitigation |
|---------|------------|
| Confirmation bias | Focus on refuting, not confirming |
| Anchoring | Generate hypotheses BEFORE reviewing evidence |
| Availability bias | Include hypotheses beyond recent memory |
| Mirror imaging | Don't assume adversary thinks like you |
| Groupthink | Document dissenting views |

## Integration with Diamond Model

```
Diamond Model (WHAT happened)
         ↓
    Evidence extraction
         ↓
ACH Analysis (WHO/WHY)
         ↓
  Calibrated attribution
         ↓
    Final Report
```

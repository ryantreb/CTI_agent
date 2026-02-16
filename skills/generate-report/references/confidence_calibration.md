# Confidence Calibration Reference (ICD 203)

## Purpose

This reference provides standardized probability language for intelligence assessments, based on Intelligence Community Directive 203 (ICD 203) standards.

## Probability Terms

| Term | Probability Range | Numeric | Usage Guidance |
|------|-------------------|---------|----------------|
| **Almost certain** | >95% | 0.95-1.00 | Reserved for near-definitive conclusions with overwhelming evidence. Use sparingly. |
| **Highly likely** | 80-95% | 0.80-0.95 | Strong evidence with minimal plausible alternatives. Most confident routine assessment. |
| **Likely** | 60-80% | 0.60-0.80 | Preponderance of evidence supports; some alternatives exist but less plausible. |
| **Roughly even chance** | 40-60% | 0.40-0.60 | Evidence is balanced, insufficient, or contradictory. Explicitly acknowledge uncertainty. |
| **Unlikely** | 20-40% | 0.20-0.40 | More evidence refutes than supports; possible but not probable. |
| **Highly unlikely** | 5-20% | 0.05-0.20 | Strong evidence against; theoretically possible but improbable. |
| **Remote possibility** | <5% | 0.00-0.05 | Cannot be excluded logically but no supporting evidence exists. |

## Format Requirements

### Standard Format
```
We assess [ASSESSMENT] (**Confidence**: [TERM])
```

### With Evidence Basis
```
We assess [ASSESSMENT] (**Confidence**: [TERM]) based on [PRIMARY EVIDENCE].
```

### With Alternatives
```
We assess [ASSESSMENT] (**Confidence**: [TERM]). Alternative explanations include 
[ALTERNATIVE], which we consider [ALTERNATIVE CONFIDENCE TERM].
```

## Examples

### Good Examples ✅

> We assess APT29 is responsible for this intrusion (**Confidence**: Likely) based on 
> TTP overlap with previous APT29 operations and infrastructure reuse.

> We assess the malware will establish persistence (**Confidence**: Highly likely) 
> given the observed registry modifications and scheduled task creation.

> We assess the campaign will expand to additional sectors (**Confidence**: Roughly even chance) 
> due to insufficient data on adversary intent.

### Bad Examples ❌

> We are certain APT29 did this.
> *(No calibration, overclaims certainty)*

> The malware probably does persistence.  
> *(Informal language, no calibration)*

> This is definitely a nation-state operation.
> *(Overclaims, no evidence basis)*

## Prohibited Language

| Prohibited | Why | Use Instead |
|------------|-----|-------------|
| "We are certain/sure" | Overclaims certainty | "Almost certain" or "Highly likely" |
| "Definitely/Obviously" | Informal, overclaims | Appropriate confidence term |
| "We believe/think" | Vague, uncalibrated | "We assess... (Confidence: X)" |
| "Probably/Maybe" | Informal, uncalibrated | "Likely" or "Roughly even chance" |
| "100%/0%" | Absolute certainty inappropriate | Appropriate probability range |

## Confidence vs. Credibility

**Confidence** = How certain we are in our assessment  
**Credibility** = How reliable the source is

These are separate concepts:
- High credibility source + limited data = Lower confidence
- Lower credibility source + corroborating evidence = Higher confidence

Always state both when relevant:
> Based on [SOURCE] (credibility: [HIGH/MEDIUM/LOW]), we assess... (**Confidence**: [TERM])

## Aggregating Multiple Sources

When multiple sources inform an assessment:

| Source Agreement | Confidence Impact |
|------------------|-------------------|
| All sources agree | Increase confidence |
| Most sources agree | Maintain stated confidence |
| Sources disagree | Decrease confidence, note disagreement |
| Single source only | Lower confidence, note limitation |

## Updating Assessments

When new evidence emerges:
1. State previous assessment and confidence
2. Describe new evidence
3. State updated assessment with new confidence
4. Explain what changed

Example:
> Our previous assessment (Likely) that APT29 was responsible has been upgraded to 
> **Highly likely** following [NEW EVIDENCE] which [EXPLANATION].

## Key Assumptions

Always document assumptions that underpin assessments:
- What are we assuming is true?
- If this assumption is wrong, how would it change our assessment?

## Intelligence Gaps

Always identify what we don't know:
- What information would increase our confidence?
- What alternative explanations haven't we fully investigated?

---

*Reference: Intelligence Community Directive 203 (ICD 203)*  
*Analytic Standards for Intelligence Community Analysis*

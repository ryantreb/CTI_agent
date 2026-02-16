---
name: self-evolving-loop
description: Implement continuous improvement through automated evaluation, prompt optimization, and version-controlled skill updates. Use at end of session to assess skill performance and trigger optimization when scores fall below thresholds. Core learning mechanism for the agent.
---

# Self-Evolving Loop Skill

## Purpose
Enable autonomous improvement through quantitative evaluation, meta-prompt optimization, and safe version control.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SELF-EVOLVING LOOP                        │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐│
│  │ Execute  │ →  │ Evaluate │ →  │ Optimize │ →  │ Deploy ││
│  │  Task    │    │ (Graders)│    │ (Meta-   │    │ Update ││
│  │          │    │          │    │  prompt) │    │        ││
│  └──────────┘    └──────────┘    └──────────┘    └────────┘│
│       ↑                                              │      │
│       └──────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Evaluation Graders

Four graders assess output quality. See `evaluation/graders/` for implementations.

### Grader 1: TTP Coverage
**Purpose**: Verify TTPs from source appear in output
**Pass Threshold**: 0.80
```python
# Measures % of T#### patterns from source found in output
# Score = len(source_ttps ∩ output_ttps) / len(source_ttps)
```

### Grader 2: IOC Fidelity  
**Purpose**: Verify IOCs are valid and not fabricated
**Pass Threshold**: 0.90
```python
# Extracts IOCs from output, validates format
# Checks all output IOCs exist in source (no hallucination)
# Score = 0.0 if any fabricated IOC found
```

### Grader 3: Framework Compliance
**Purpose**: Verify required report sections present
**Pass Threshold**: 0.85
```python
# Checks for: Executive Summary, Key Judgments, ATT&CK table,
# IOCs, Defensive Recommendations, Gaps/Assumptions
# Score = sections_present / sections_required
```

### Grader 4: Analytical Quality (LLM-as-Judge)
**Purpose**: Assess reasoning quality via rubric
**Pass Threshold**: 0.75
```
Rubric:
  1.0 = Exemplary: Calibrated confidence, clear judgments, evidence cited
  0.75 = Good: Most elements present, minor gaps
  0.5 = Adequate: Basic structure, assumptions unstated
  0.25 = Poor: Missing sections, unsupported claims
  0.0 = Unacceptable: Fabrications or contradictions
```

## Evaluation Protocol

```
FOR EACH skill_output IN session:
  1. RUN all 4 graders
  2. CALCULATE aggregate_score = mean(grader_scores)
  3. LOG to state/eval_history.jsonl:
     {
       "timestamp": "ISO8601",
       "skill": "skill_name",
       "version": current_version,
       "scores": {grader: score},
       "aggregate": aggregate_score,
       "passed": aggregate_score >= 0.80
     }
  4. IF aggregate_score < 0.80:
       TRIGGER optimization
```

## Meta-Prompt Optimization

When a skill underperforms, invoke the optimizer:

```markdown
# META-PROMPT TEMPLATE

## Context
- **Skill**: {skill_name}
- **Current Prompt**: {skill_prompt}
- **Task Input**: {input_sample}
- **Task Output**: {output_sample}
- **Grader Scores**: 
  - TTP Coverage: {score} (threshold: 0.80)
  - IOC Fidelity: {score} (threshold: 0.90)
  - Framework Compliance: {score} (threshold: 0.85)
  - Analytical Quality: {score} (threshold: 0.75)
- **Failure Analysis**: {which graders failed and why}

## Task
Generate an improved version of the skill prompt that:
1. Addresses the specific failures identified
2. Maintains all capabilities that passed
3. Adds explicit instructions to prevent failure modes
4. Does not increase prompt length by more than 20%

## Constraints (IMMUTABLE)
- Do NOT remove safety guardrails
- Do NOT remove framework compliance requirements
- Do NOT remove confidence calibration language
- Preserve output schema structure

## Output
Return ONLY the improved skill prompt text. No explanation.
```

## Version Control

### Skill Version Entry
```json
{
  "version": 1,
  "skill": "generate-report",
  "prompt_hash": "sha256_of_prompt",
  "timestamp": "ISO8601",
  "eval_scores": {
    "ttp_coverage": 0.85,
    "ioc_fidelity": 0.95,
    "framework_compliance": 0.90,
    "analytical_quality": 0.80
  },
  "aggregate_score": 0.875,
  "status": "production|candidate|deprecated"
}
```

### Version State File
Location: `state/skill_versions.json`
```json
{
  "skills": {
    "generate-report": {
      "current_version": 2,
      "versions": [/* version entries */]
    }
  }
}
```

## Safety Constraints (IMMUTABLE)

### Never Optimize Away
- Framework compliance requirements
- Confidence calibration language
- Source citation requirements
- Output schema structure
- Prime Directives from AGENT.md

### Automatic Rollback Triggers
- New version scores 10%+ worse than previous
- 3+ consecutive failures after update
- Any grader returns < 0.3
- Human override flag set

### Change Limits
- Maximum 1 skill update per session
- Maximum 20% prompt length increase
- Changes must be diff-reviewable
- Backup created before every edit

## Learning Log

All evaluations logged to `state/eval_history.jsonl`:
```json
{"timestamp": "...", "skill": "...", "version": 1, "scores": {...}, "passed": true}
{"timestamp": "...", "skill": "...", "version": 1, "scores": {...}, "passed": false, "optimization_triggered": true}
{"timestamp": "...", "skill": "...", "version": 2, "scores": {...}, "passed": true}
```

## Cross-Session Learning

At session start:
```
1. LOAD state/eval_history.jsonl
2. IDENTIFY failure patterns:
   - Same grader failing repeatedly?
   - Same skill underperforming?
3. IF pattern detected (3+ occurrences):
     FLAG for human review
     ADD to memory/scratchpad.md as known issue
4. IF model drift detected (scores declining over 5 sessions):
     TRIGGER comprehensive skill review
```

## Human Escalation

Escalate to human when:
- Same failure 3+ times despite optimization
- Grader consistently returns < 0.5
- Conflicting optimization suggestions
- Safety constraint potentially affected

Escalation format:
```markdown
## Optimization Escalation Required

**Skill**: {skill_name}
**Issue**: {description}
**Attempted Fixes**: {list of optimization attempts}
**Current Scores**: {grader scores}
**Recommendation**: {suggested human action}
```

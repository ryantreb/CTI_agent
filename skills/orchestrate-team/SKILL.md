---
name: orchestrate-team
description: Coordinate the 5-agent intelligence team pipeline (Collector → Analyst → Devil's Advocate ↔ Analyst → Verifier → Reporter). Use when running a full intelligence analysis session with adversarial review and independent verification.
---

# Team Orchestration Skill

## Purpose
Coordinate the multi-agent intelligence team to execute a full analysis pipeline with adversarial challenge and independent verification.

## Team Composition

| Agent | Definition | Role |
|-------|-----------|------|
| Collector | `agents/definitions/collector.md` | Gather and enrich intelligence |
| Analyst | `agents/definitions/analyst.md` | Analyze and assess |
| Devil's Advocate | `agents/definitions/devils_advocate.md` | Challenge assessments |
| Verifier | `agents/definitions/verifier.md` | Validate all claims |
| Reporter | `agents/definitions/reporter.md` | Produce deliverables |

## Pipeline Flow

```
Phase 1: COLLECT
  Collector agent executes:
    check-server-health → recall-intelligence → monitor-feeds → enrich-iocs
  OUTPUT: collection_bundle

Phase 2: ANALYZE
  Analyst agent executes:
    diamond-model-analysis → analysis-competing-hypotheses
  OUTPUT: assessment_package

Phase 3: DEBATE
  Devil's Advocate ↔ Analyst exchange:
    FOR round IN 1..MAX_ROUNDS:
      DA constructs challenges (lib/debate)
      Analyst responds with rebuttals/adjustments
      CHECK consensus (lib/debate.check_consensus)
      IF consensus: BREAK
    DOCUMENT dissenting views
  OUTPUT: debate_record

Phase 4: VERIFY
  Verifier agent executes:
    extract_claims → classify_claims → verify-claims → detect_hallucinations
  OUTPUT: verification_report

Phase 5: REPORT
  Reporter agent executes:
    generate-report → produce-stix-bundle → produce-attack-layers
  OUTPUT: Final deliverables
```

## Execution Protocol

### Step 1: Initialize Team Session
```
GENERATE session_id (UUID)
LOG team_session_start to logs/{date}.jsonl
LOAD team config from config/team_config.json
```

### Step 2: Execute Collection Phase
```
ACTIVATE Collector agent (agents/definitions/collector.md)
WAIT for collection_bundle output
VALIDATE: collection_bundle has enriched_iocs
IF empty: LOG "no new intelligence", SKIP to metrics
```

### Step 3: Execute Analysis Phase
```
ACTIVATE Analyst agent (agents/definitions/analyst.md)
PASS: collection_bundle
WAIT for assessment_package output
VALIDATE: assessment_package has key_judgments
```

### Step 4: Execute Debate Phase
```
ACTIVATE Devil's Advocate agent (agents/definitions/devils_advocate.md)
PASS: assessment_package

DEBATE LOOP:
  DA generates challenges
  PASS challenges to Analyst for response
  Analyst provides rebuttals/adjustments
  CHECK consensus
  IF consensus OR round >= 3: EXIT loop

CAPTURE debate_record
```

### Step 5: Execute Verification Phase
```
ACTIVATE Verifier agent (agents/definitions/verifier.md)
PASS: debate_record (includes assessment_package)
WAIT for verification_report
LOG: verified_count, refuted_count, hallucination_flags
```

### Step 6: Execute Reporting Phase
```
ACTIVATE Reporter agent (agents/definitions/reporter.md)
PASS: verification_report + debate_record
WAIT for final outputs:
  - reports/{guid}.md
  - reports/{guid}_stix_bundle.json
  - reports/{guid}_attack_layer.json
  - reports/{guid}_detections/
```

### Step 7: Finalize Session
```
RECORD session metrics via lib/metrics
UPDATE state files
LOG team_session_end
```

## Error Handling

| Failure | Recovery |
|---------|----------|
| Collector returns empty | Log, skip session gracefully |
| Analyst fails | Log error, attempt with reduced input |
| Debate exceeds MAX_ROUNDS | Force document dissent, continue to Verifier |
| Verifier API errors | Mark claims UNVERIFIED, continue |
| Reporter fails | Log, save partial outputs |
| Any agent crash | Log, save state, alert user |

## Rationale

This pipeline addresses two critical LLM failure modes:
1. **Confirmation bias**: Devil's Advocate has structural mandate to challenge
2. **Hallucination**: Verifier independently re-validates every claim against source APIs

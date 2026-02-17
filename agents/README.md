# CTI Agent Agent Definitions

Agent role definitions for the multi-agent intelligence team (v2.4.0).

| Agent | File | Role |
|-------|------|------|
| Collector | `definitions/collector.md` | Parallel feed monitoring and IOC enrichment |
| Analyst | `definitions/analyst.md` | Diamond Model analysis, ACH, hypothesis generation |
| Devil's Advocate | `definitions/devils_advocate.md` | Adversarial challenge of assessments |
| Verifier | `definitions/verifier.md` | Independent claim validation |
| Reporter | `definitions/reporter.md` | Final product assembly |

## Pipeline Flow

```
Collector → Analyst → [Devil's Advocate ↔ Analyst debate] → Verifier → Reporter
```

## Data Handoffs

| From | To | Data Structure |
|------|----|---------------|
| Collector | Analyst | `collection_bundle` |
| Analyst | Devil's Advocate | `assessment_package` |
| DA ↔ Analyst | Verifier | `debate_record` |
| Verifier | Reporter | `verification_report` |

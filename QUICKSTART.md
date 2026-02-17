# CTI Agent - Quick Start Guide

## Overview

CTI Agent is a self-evolving threat intelligence system that combines:
- **MCP-native intelligence collection** (Feedly, GTI/VirusTotal)
- **Professional analytical tradecraft** (Diamond Model, ACH, ATT&CK)
- **Continuous self-improvement** (quantitative graders, meta-prompt optimization)

## Prerequisites

### Required API Keys

Set these environment variables before use:

```bash
# VirusTotal / Google Threat Intelligence
export VT_API_KEY="your_virustotal_api_key"

# Feedly (requires Feedly TI subscription)
export FEEDLY_ACCESS_TOKEN="your_feedly_token"

# Optional: Additional enrichment sources
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export OTX_API_KEY="your_otx_key"
```

### MCP Server Setup

Install required MCP servers:

```bash
# GTI (VirusTotal)
pip install gti-mcp

# Feedly
pip install feedly-mcp

# Multi-source enrichment
pip install fastmcp-threatintel
```

## Directory Structure

```
junior-threat-intel-agent/
├── AGENT.md                    # Master orchestrator (read this first)
├── skills/                     # Skill definitions
│   ├── plan-session/          # Session planning
│   ├── monitor-feeds/         # Intelligence collection
│   ├── enrich-iocs/           # IOC enrichment
│   ├── diamond-model-analysis/ # Intrusion analysis
│   ├── analysis-competing-hypotheses/ # Attribution
│   ├── generate-report/       # Report generation
│   └── self-evolving-loop/    # Self-improvement
├── evaluation/                 # Graders and validators
│   ├── graders/               # Python grader scripts
│   └── eval_runner.py         # Evaluation orchestrator
├── config/                     # Configuration files
├── state/                      # Persistent state
├── memory/                     # Session working memory
├── templates/                  # Report templates
├── logs/                       # Event logs
└── reports/                    # Generated reports
```

## Basic Usage

### 1. Initialize a Session

The agent reads `AGENT.md` first, then:
1. Loads state from `state/active_context.md`
2. Creates/loads `memory/scratchpad.md`
3. Executes `plan-session` skill

### 2. Execute Intelligence Cycle

```
plan-session → monitor-feeds → enrich-iocs → diamond-model-analysis 
            → analysis-competing-hypotheses → generate-report
```

### 3. Self-Improvement (Optional)

After producing outputs, run `self-evolving-loop` to:
- Evaluate outputs against 4 graders
- Identify underperforming skills
- Trigger meta-prompt optimization if needed

## Key Concepts

### Intelligence Frameworks

| Framework | Purpose | When Used |
|-----------|---------|-----------|
| Diamond Model | Structure intrusion data | After IOC enrichment |
| ACH | Test attribution hypotheses | When attribution uncertain |
| Kill Chain | Map attack phases | During analysis |
| ATT&CK | Standardize TTPs | Throughout |

### Confidence Calibration

All assessments use ICD 203 probability language:
- **Almost certain**: >95%
- **Highly likely**: 80-95%
- **Likely**: 60-80%
- **Roughly even chance**: 40-60%
- **Unlikely**: 20-40%

### Self-Improvement Graders

| Grader | Threshold | Purpose |
|--------|-----------|---------|
| TTP Coverage | 0.80 | Verify TTPs captured |
| IOC Fidelity | 0.90 | Prevent hallucination |
| Framework Compliance | 0.85 | Ensure structure |
| Analytical Quality | 0.75 | Assess reasoning |

## Output Locations

| Output | Location |
|--------|----------|
| Intelligence Reports | `reports/{guid}.md` |
| Detection Rules | `reports/{guid}_detections/` |
| IOC Lists | `reports/{guid}_iocs.json` |
| Session Logs | `logs/{date}.jsonl` |

## Troubleshooting

### MCP Server Not Responding
1. Check API keys are set
2. Verify server is installed: `pip show gti-mcp`
3. Check rate limits haven't been exceeded

### Low Evaluation Scores
1. Review `state/eval_history.jsonl` for patterns
2. Check which graders are failing
3. Review `get_failure_feedback()` output
4. Let self-evolving-loop optimize, or manually adjust skill

### State Corruption
1. Backup current state files
2. Reset to defaults from templates
3. Re-run session from clean state

## Next Steps

1. Read `AGENT.md` for full architecture
2. Review skill files in `skills/` directory
3. Configure MCP servers in `config/mcp_config.json`
4. Run first session and review outputs

---

*CTI Agent v1.0.0*

# CTI Agent - Quick Start Guide

**Version**: 2.4.0

## Overview

CTI Agent is a multi-agent cyber threat intelligence system that combines:
- **17 MCP server integrations** across 6 categories (intelligence, enrichment, vulnerability, malware analysis, OSINT, utility)
- **5-agent team** with adversarial review and independent verification
- **Professional analytical tradecraft** (Diamond Model, ACH, ATT&CK, ICD 203)
- **Anti-hallucination verification** (5-tier claim validation with quarantine)
- **Continuous self-improvement** (quantitative graders, meta-prompt optimization)

## Prerequisites

### Required API Keys

```bash
cp config/.env.template config/.env
# Edit config/.env with your API keys
```

11 of 17 MCP servers require **no API keys** and work immediately.

**Recommended** (free tier available):
- `VT_API_KEY` — VirusTotal / Google Threat Intelligence (1000 req/day)
- `OTX_API_KEY` — AlienVault OTX (free, generous limits)
- `ABUSEIPDB_API_KEY` — AbuseIPDB (1000 req/day)
- `SHODAN_API_KEY` — Shodan (100 queries/month)

**Optional** (free tier):
- `TI_MINDMAP_API_KEY` — TI Mindmap HUB (free from ti-mindmap-hub.com)

### MCP Server Setup

Most servers auto-install via `uvx` when Claude Code loads `.mcp.json`. For manual installation:

```bash
uvx gti_mcp
pip install fastmcp-threatintel
```

See `config/mcp_server_registry.json` for the full 17-server registry.

## Directory Structure

```
CTI_agent/
├── AGENT.md                         # Master orchestrator (start here)
├── agents/definitions/              # Multi-agent team definitions
│   ├── collector.md                 #   Feed monitoring + IOC enrichment
│   ├── analyst.md                   #   Diamond Model + ACH analysis
│   ├── devils_advocate.md           #   Adversarial challenge protocol
│   ├── verifier.md                  #   Independent claim validation
│   └── reporter.md                  #   Final product assembly
├── skills/                          # 13 skill prompt files
│   ├── orchestrate-team/            #   5-agent pipeline coordinator
│   ├── monitor-feeds/               #   Intelligence collection
│   ├── enrich-iocs/                 #   Multi-source IOC enrichment
│   ├── verify-claims/               #   Claim validation + hallucination detection
│   ├── diamond-model-analysis/      #   Structured intrusion analysis
│   ├── analysis-competing-hypotheses/ # Attribution hypothesis testing
│   ├── generate-report/             #   ICD 203 intelligence reports
│   ├── produce-stix-bundle/         #   STIX 2.1 output
│   ├── produce-attack-layers/       #   ATT&CK Navigator layers
│   ├── recall-intelligence/         #   Pinecone vector memory
│   ├── check-server-health/         #   MCP server availability
│   ├── plan-session/                #   Session planning
│   └── self-evolving-loop/          #   Meta-prompt optimization
├── lib/                             # Python deterministic logic (12 modules)
├── evaluation/                      # Quality assessment graders
├── config/                          # Configuration files
├── tests/                           # 182 tests
├── state/                           # Runtime state files
└── reports/                         # Generated intelligence products
```

## Basic Usage

### 1. Single-Agent Session

```
Read AGENT.md and begin a threat intelligence session.
Focus on [YOUR PRIORITY - e.g., "APT activity", "ransomware trends", "CVE-2025-XXXX"]
```

Pipeline: `plan-session → monitor-feeds → enrich-iocs → diamond-model-analysis → analysis-competing-hypotheses → generate-report`

### 2. Full Multi-Agent Pipeline

```
Read AGENT.md and run the orchestrate-team skill for a complete intelligence cycle.
```

Pipeline: `Collector → Analyst → [Devil's Advocate ↔ Analyst debate] → Verifier → Reporter`

### 3. Self-Improvement (Optional)

After producing outputs, run `self-evolving-loop` to evaluate against 4 graders and trigger meta-prompt optimization if needed.

## Multi-Agent Team

| Agent | Role | Skills |
|-------|------|--------|
| **Collector** | Gather and enrich raw intelligence | monitor-feeds, enrich-iocs |
| **Analyst** | Produce calibrated assessments | diamond-model, ACH |
| **Devil's Advocate** | Challenge high-confidence judgments | ACH (adversarial) |
| **Verifier** | Independently re-validate all claims | verify-claims |
| **Reporter** | Assemble final deliverables | generate-report, STIX, ATT&CK |

**Why multi-agent?** The Devil's Advocate structurally prevents confirmation bias by challenging all assessments rated "highly likely" or above. The Verifier independently re-queries source APIs for every claim — refuted claims are quarantined and never reach the final report.

## Key Concepts

### Intelligence Frameworks

| Framework | Purpose | When Used |
|-----------|---------|-----------|
| Diamond Model | Structure intrusion data (Adversary, Infrastructure, Capability, Victim) | After IOC enrichment |
| ACH | Test attribution hypotheses with diagnosticity matrix | When attribution uncertain |
| Kill Chain / ATT&CK | Map attack phases and standardize TTPs | Throughout analysis |

### Confidence Calibration (ICD 203)

| Term | Probability |
|------|-------------|
| Almost certain | >95% |
| Highly likely | 80-95% |
| Likely | 60-80% |
| Roughly even chance | 40-60% |
| Unlikely | 20-40% |

### Verification Gate

All claims pass through a 5-tier system before reaching the final report:

| Status | Confidence Multiplier | Handling |
|--------|----------------------|----------|
| `VERIFIED_HIGH` | 1.0x | Include as stated |
| `VERIFIED_MEDIUM` | 0.75x | Include with caveat |
| `VERIFIED_LOW` | 0.5x | Include with strong caveat |
| `UNVERIFIED` | 0.25x | Prefix with `[UNVERIFIED]` |
| `REFUTED` | 0.0x | Suppress entirely |

### Evaluation Graders

| Grader | Threshold | Purpose |
|--------|-----------|---------|
| TTP Coverage | 0.80 | Verify TTPs captured |
| IOC Fidelity | 0.90 | Prevent hallucination |
| Framework Compliance | 0.85 | Ensure structure |
| Analytical Quality | 0.70 | Assess reasoning |

## Output Products

| Product | Format | Location |
|---------|--------|----------|
| Intelligence Reports | Markdown (ICD 203) | `reports/{guid}.md` |
| STIX 2.1 Bundles | JSON | `reports/{guid}_stix_bundle.json` |
| ATT&CK Navigator Layers | JSON (v4.5) | `reports/{guid}_attack_layer.json` |
| Detection Rules | Sigma / YARA | `reports/{guid}_detections/` |
| IOC Packages | STIX 2.1 JSON | `reports/{guid}_iocs.json` |

## Troubleshooting

### MCP Server Not Responding
1. Run `check-server-health` skill to diagnose
2. Check API keys are set in `config/.env`
3. Verify server is installed: `pip show gti-mcp`
4. Check rate limits haven't been exceeded

### Low Evaluation Scores
1. Review `state/eval_history.jsonl` for patterns
2. Check which graders are failing
3. Let self-evolving-loop optimize, or manually adjust skill

### State Corruption
1. Backup current state files
2. Reset to defaults from templates
3. Re-run session from clean state

## Next Steps

1. Read `AGENT.md` for the full orchestrator
2. Read `docs/ARCHITECTURE.md` for system architecture
3. Read `docs/DEVELOPMENT.md` for development guide
4. Configure MCP servers in `config/mcp_server_registry.json`
5. Run first session and review outputs

---

*CTI Agent v2.4.0 — Multi-agent intelligence team with adversarial review and independent verification.*

# CTI Agent

**Version**: 2.4.0

Autonomous multi-agent cyber threat intelligence system with professional analytical tradecraft, 23 MCP server integrations, and built-in anti-hallucination verification.

---

## Overview

CTI Agent is a prompt-orchestrated, multi-agent threat intelligence system that:

1. **Collects** threat intelligence from 23 MCP servers across 6 categories
2. **Enriches** IOCs with multi-source data and dynamic routing
3. **Analyzes** threats using Diamond Model and ACH frameworks
4. **Challenges** assessments through adversarial Devil's Advocate debate
5. **Verifies** every claim independently before reporting (anti-hallucination)
6. **Produces** calibrated intelligence reports, STIX 2.1 bundles, and ATT&CK layers
7. **Improves** itself through quantitative evaluation and prompt optimization

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CTI Agent v2.4.0                              │
│           Multi-Agent Intelligence with Adversarial Review           │
└──────────────────────────────────────────────────────────────────────┘

  Collector → Analyst → [Devil's Advocate ↔ Analyst] → Verifier → Reporter
      │           │              │                         │           │
  monitor-    diamond-      challenge high-          re-query      generate
  feeds       model         confidence              source        report
  enrich-     ACH           assessments             APIs          STIX 2.1
  iocs        analysis      propose alt.            detect        ATT&CK
                            hypotheses              hallucination layers
```

---

## Quick Start

### 1. Configure API Keys

```bash
cp config/.env.template config/.env
# Edit config/.env with your API keys
```

13 of 23 MCP servers require **no API keys** and work immediately (vulnerability intel, abuse feeds, ORKL threat reports, DNS recon, and more).

**Recommended Keys** (free tier available):
- `VT_API_KEY` — VirusTotal / Google Threat Intelligence
- `OTX_API_KEY` — AlienVault OTX
- `ABUSEIPDB_API_KEY` — AbuseIPDB
- `SHODAN_API_KEY` — Shodan

**Optional Keys** (free tier or paid):
- `CENSYS_API_ID` / `CENSYS_API_SECRET` — Censys
- `FEEDLY_ACCESS_TOKEN` — Feedly Threat Intelligence (paid subscription)
- `MALLORY_API_KEY` — Mallory real-time threats

### 2. Install MCP Servers

Most servers auto-install via `uvx` when Claude Code loads `.mcp.json`. For manual installation:

```bash
uvx gti_mcp
pip install fastmcp-threatintel
```

See `config/mcp_server_registry.json` for the full 23-server registry.

### 3. Run the Agent

In Claude Code:

```
Read AGENT.md and begin a threat intelligence session.
Focus on [YOUR PRIORITY - e.g., "APT activity", "ransomware trends", "CVE-2025-XXXX"]
```

For the full multi-agent pipeline:

```
Read AGENT.md and run the orchestrate-team skill for a complete intelligence cycle.
```

---

## Multi-Agent Team (v2.4.0)

Five specialized agents with structural separation of concerns:

| Agent | Role | Skills |
|-------|------|--------|
| **Collector** | Gather and enrich raw intelligence | monitor-feeds, enrich-iocs |
| **Analyst** | Produce calibrated assessments | diamond-model, ACH |
| **Devil's Advocate** | Challenge high-confidence judgments | ACH (adversarial) |
| **Verifier** | Independently re-validate all claims | verify-claims |
| **Reporter** | Assemble final deliverables | generate-report, STIX, ATT&CK |

### Why Multi-Agent?

This pipeline addresses two critical LLM failure modes:

1. **Confirmation bias** — The Devil's Advocate has a structural mandate to challenge all assessments rated "highly likely" or above, argue for alternative hypotheses, and document dissenting views per [ICD 203](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf)
2. **Hallucination** — The Verifier independently re-queries source APIs for every IOC, TTP, and attribution claim. Refuted claims are quarantined and never reach the final report

### Pipeline Data Flow

```
collection_bundle → assessment_package → debate_record → verification_report → final deliverables
    (Collector)        (Analyst)          (DA ↔ Analyst)    (Verifier)           (Reporter)
```

---

## Project Structure

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
│   ├── self-evolving-loop/          #   Meta-prompt optimization
│   └── external/                    #   Third-party skills
├── lib/                             # Python deterministic logic (12 modules)
│   ├── team_data.py                 #   Inter-agent data schemas
│   ├── debate.py                    #   Devil's Advocate debate engine
│   ├── verification_pipeline.py     #   Claim extraction + routing
│   ├── stix_builder.py              #   Diamond Model → STIX 2.1
│   ├── attack_layers.py             #   Diamond Model → ATT&CK Navigator
│   ├── confidence_decay.py          #   IOC freshness half-life calculations
│   ├── actor_profiles.py            #   Persistent threat actor profiles
│   ├── pinecone_memory.py           #   Vector memory for historical context
│   ├── health_check.py              #   MCP server health checks
│   ├── config.py                    #   Registry loader + routing tables
│   ├── metrics.py                   #   Observability metrics
│   └── logging_schema.py            #   Structured JSONL logging
├── evaluation/                      # Quality assessment graders
├── config/                          # Configuration
│   ├── mcp_server_registry.json     #   23 MCP servers (source of truth)
│   ├── mcp_config.json              #   Claude Code MCP config (generated)
│   ├── team_config.json             #   Multi-agent pipeline config
│   ├── skill_ownership.json         #   Skill conflict resolution
│   └── feeds.json                   #   RSS fallback feeds
├── tests/                           # 182 tests
├── demo/                            # Demo dataset + mock MCP responses
├── docs/                            # Architecture + development docs
├── state/                           # Runtime state files
└── reports/                         # Generated intelligence products
```

---

## MCP Server Integrations

23 servers across 6 categories with dynamic routing and graceful degradation:

| Category | Servers | Purpose |
|----------|---------|---------|
| **Intelligence** | Feedly, OTX, ORKL, TI Mindmap HUB, Mallory | Threat feed collection |
| **Enrichment** | GTI/VirusTotal, Shodan, Censys, fastmcp-threatintel | IOC enrichment |
| **Vulnerability** | NVD, KEV, EPSS, Vulnerability Intelligence, Nuclei | CVE intelligence |
| **Malware Analysis** | Ghidra, YARA, Capa, Radare2, Binwalk | Binary analysis |
| **OSINT** | DNSTwist, NetworksDB | DNS + network recon |
| **Utility** | CyberChef | Data transformation |

IOC routing is configured per type (IP, domain, hash, URL, CVE) with primary/secondary/fallback chains. The `check-server-health` skill adjusts routing at session start based on available API keys and server status.

---

## Analytical Frameworks

### Diamond Model

Structures intrusion analysis into four vertices:
- **Adversary** — Who conducted the attack
- **Infrastructure** — Systems used (C2, delivery)
- **Capability** — Tools and techniques (mapped to ATT&CK)
- **Victim** — Target of the attack

### Analysis of Competing Hypotheses (ACH)

Seven-step process for rigorous attribution:
1. Generate all plausible hypotheses (including deception + null)
2. List all evidence from Diamond Model
3. Create diagnosticity matrix
4. Refine hypotheses
5. Assess diagnostic evidence (focus on refuting, not confirming)
6. Calculate likelihood
7. Report with calibrated confidence

### Confidence Calibration (ICD 203)

| Term | Probability |
|------|-------------|
| Almost certain | >95% |
| Highly likely | 80-95% |
| Likely | 60-80% |
| Roughly even chance | 40-60% |
| Unlikely | 20-40% |
| Highly unlikely | 5-20% |
| Remote possibility | <5% |

---

## Verification Gate

All claims pass through a 5-tier verification system before reaching the final report:

| Status | Confidence Multiplier | Handling |
|--------|----------------------|----------|
| `VERIFIED_HIGH` | 1.0x | Include as stated |
| `VERIFIED_MEDIUM` | 0.75x | Include with caveat |
| `VERIFIED_LOW` | 0.5x | Include with strong caveat |
| `UNVERIFIED` | 0.25x | Prefix with `[UNVERIFIED]` |
| `REFUTED` | 0.0x | Suppress entirely |

Hallucination detection flags:
- Claims with no source verification possible
- Refutation rate >=50% across all claims
- Attribution claims supported by only 1 source

---

## Output Products

| Product | Format | Location |
|---------|--------|----------|
| Intelligence Reports | Markdown (ICD 203) | `reports/{guid}.md` |
| STIX 2.1 Bundles | JSON | `reports/{guid}_stix_bundle.json` |
| ATT&CK Navigator Layers | JSON (v4.5) | `reports/{guid}_attack_layer.json` |
| Detection Rules | Sigma / YARA | `reports/{guid}_detections/` |
| IOC Packages | STIX 2.1 JSON | `reports/{guid}_iocs.json` |

Reports include: executive summary, key judgments with calibrated confidence, Diamond Model summary, ATT&CK mapping, ACH summary, **Alternative Analysis** (from Devil's Advocate debate), verified IOC tables, defensive recommendations, assumptions, intelligence gaps, and reassessment triggers.

---

## Evaluation System

Four graders assess output quality:

| Grader | Measures | Threshold |
|--------|----------|-----------|
| `ttp_coverage` | TTP extraction completeness | 0.80 |
| `ioc_fidelity` | IOC accuracy (0 if hallucinated) | 0.90 |
| `framework_compliance` | Required report sections present | 0.85 |
| `analytical_quality` | Reasoning quality (LLM judge) | 0.70 |

The self-evolving loop evaluates outputs, identifies underperforming skills, and triggers meta-prompt optimization with automatic rollback on regression.

---

## Development

```bash
# Run tests (182 passing)
uv run --with pytest python -m pytest -q

# Lint + format
ruff check . --fix && ruff format .
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the full development guide and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system architecture.

---

## External Skills

| Source | Skills | Purpose |
|--------|--------|---------|
| [gl0bal01/malware-analysis](https://github.com/gl0bal01/malware-analysis-claude-skills) | malware-triage, dynamic-analysis, detection-engineer | Malware analysis pipeline |
| [YARAHQ/yara-rule-skill](https://github.com/YARAHQ/yara-rule-skill) | yara-rule-skill | YARA detection rule authoring |
| [trailofbits/skills](https://github.com/trailofbits/skills) | variant-analysis, semgrep, static-analysis | Security analysis |

---

## Version History

| Version | Focus |
|---------|-------|
| **v2.4.0** | Multi-agent team (5 agents), debate engine, verification pipeline |
| v2.3.0 | Confidence decay, actor profiles, Pinecone memory, metrics |
| v2.2.0 | STIX 2.1 builder, ATT&CK layers, external skills, demo dataset |
| v2.1.0 | 23 MCP servers, dynamic routing, health checks, evaluation graders |

---

## Roadmap

- [x] Core architecture + skills
- [x] 23 MCP server integrations with dynamic routing
- [x] STIX 2.1 + ATT&CK Navigator output
- [x] External skill integration (malware analysis, YARA, Trail of Bits)
- [x] Confidence decay + threat actor profiles
- [x] Pinecone vector memory for historical context
- [x] Multi-agent team with adversarial review
- [x] Independent verification pipeline + hallucination detection
- [ ] SecOps SIEM integration
- [ ] SOAR playbook generation
- [ ] Web dashboard
- [ ] Historical trend analysis

---

## References

- [Diamond Model of Intrusion Analysis](https://apps.dtic.mil/sti/citations/ADA586960)
- [Psychology of Intelligence Analysis (Heuer)](https://www.cia.gov/resources/csi/books-and-monographs/psychology-of-intelligence-analysis-2/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ICD 203 Analytic Standards](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf)

---

## License

MIT License

---

*CTI Agent v2.4.0 — Multi-agent intelligence team with adversarial review and independent verification.*

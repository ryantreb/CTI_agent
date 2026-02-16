# Junior Threat Intel Agent (JTIA)

**Version**: 1.0.0  
**Codename**: JTIA  

A self-evolving autonomous threat intelligence agent with professional analytical tradecraft.

---

## Overview

Junior Threat Intel Agent is an autonomous system that:

1. **Collects** threat intelligence from MCP servers (Feedly, GTI/VirusTotal)
2. **Enriches** IOCs with multi-source data
3. **Analyzes** threats using Diamond Model and ACH frameworks
4. **Produces** professional intelligence reports with calibrated confidence
5. **Improves** itself through quantitative evaluation and prompt optimization

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      JUNIOR THREAT INTEL AGENT                               │
│                    Self-Evolving + Intelligence Tradecraft                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│   ORIENT PHASE    │   │   ANALYZE PHASE   │   │   LEARN PHASE     │
│   (Collection)    │   │   (Tradecraft)    │   │   (Self-Evolve)   │
├───────────────────┤   ├───────────────────┤   ├───────────────────┤
│ • monitor-feeds   │   │ • diamond-model   │   │ • evaluation      │
│ • enrich-iocs     │   │ • ach-analysis    │   │ • optimization    │
│                   │   │ • generate-report │   │ • version control │
└───────────────────┘   └───────────────────┘   └───────────────────┘
```

---

## Quick Start

### 1. Configure API Keys

```bash
cp config/.env.template config/.env
# Edit config/.env with your API keys
```

**Required Keys**:
- `FEEDLY_API_KEY` - Feedly Threat Intelligence
- `VT_API_KEY` - VirusTotal (used by GTI MCP)

**Optional Keys**:
- `ABUSEIPDB_API_KEY` - AbuseIPDB
- `OTX_API_KEY` - AlienVault OTX

### 2. Install MCP Servers

```bash
# Feedly MCP
uvx feedly-mcp

# GTI MCP (VirusTotal)
uvx gti_mcp

# Optional: fastmcp-threatintel
pip install fastmcp-threatintel
```

### 3. Run the Agent

In Claude Code or Claude.ai with computer use:

```
Read AGENT.md and begin a threat intelligence session.
Focus on [YOUR PRIORITY - e.g., "APT activity", "ransomware trends", "CVE-2024-XXXX"]
```

---

## Project Structure

```
junior-threat-intel-agent/
├── AGENT.md                    # Master orchestrator (read this first)
│
├── skills/                     # Modular capabilities
│   ├── plan-session/           # Session planning
│   ├── monitor-feeds/          # Intelligence collection
│   ├── enrich-iocs/           # IOC enrichment
│   ├── diamond-model-analysis/ # Structured intrusion analysis
│   ├── analysis-competing-hypotheses/  # Attribution testing
│   ├── generate-report/        # Report production
│   └── self-evolving-loop/     # Continuous improvement
│
├── evaluation/                 # Quality assessment
│   ├── graders/               # Python grading scripts
│   │   ├── ttp_coverage.py
│   │   ├── ioc_fidelity.py
│   │   ├── framework_compliance.py
│   │   └── analytical_quality_judge.json
│   └── run_evaluation.py      # Evaluation orchestrator
│
├── config/                    # Configuration
│   ├── mcp_config.json        # MCP server settings
│   ├── feeds.json             # RSS feed fallback
│   └── .env.template          # API key template
│
├── templates/                 # Output templates
│   └── report_template.md
│
├── state/                     # Persistent state
│   ├── processed_guids.json   # Deduplication
│   ├── skill_versions.json    # Version control
│   └── active_context.md      # Session state
│
├── memory/                    # Working memory
│   └── scratchpad.md          # Session scratchpad
│
├── logs/                      # Event logs
│   └── reflections/           # Learning logs
│
├── reports/                   # Generated reports
└── alerts/                    # High-priority alerts
```

---

## Skills Overview

### Collection Phase

| Skill | Purpose | MCP Tools Used |
|-------|---------|----------------|
| `plan-session` | Generate execution plan | None |
| `monitor-feeds` | Collect threat intel | Feedly, web_fetch |
| `enrich-iocs` | Multi-source enrichment | GTI, fastmcp-threatintel |

### Analysis Phase

| Skill | Purpose | Framework |
|-------|---------|-----------|
| `diamond-model-analysis` | Structure intrusion data | Diamond Model |
| `analysis-competing-hypotheses` | Test attribution | ACH (Heuer) |
| `generate-report` | Produce intelligence products | ICD 203 |

### Learning Phase

| Skill | Purpose | Method |
|-------|---------|--------|
| `self-evolving-loop` | Continuous improvement | Eval + Meta-optimization |

---

## Analytical Frameworks

### Diamond Model

Structures intrusion analysis into four vertices:
- **Adversary**: Who conducted the attack
- **Infrastructure**: Systems used (C2, delivery)
- **Capability**: Tools and techniques
- **Victim**: Target of the attack

### Analysis of Competing Hypotheses (ACH)

Seven-step process for rigorous attribution:
1. Generate all plausible hypotheses
2. List all evidence
3. Create diagnosticity matrix
4. Refine hypotheses
5. Assess diagnostic evidence
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

## Evaluation System

Four graders assess output quality:

| Grader | Measures | Threshold |
|--------|----------|-----------|
| `ttp_coverage` | TTP extraction accuracy | 0.80 |
| `ioc_fidelity` | IOC accuracy (0 if hallucinated) | 0.90 |
| `framework_compliance` | Required sections present | 0.85 |
| `analytical_quality` | Reasoning quality (LLM judge) | 0.70 |

### Running Evaluation

```bash
python evaluation/run_evaluation.py source.txt output.md --json
```

---

## Self-Improvement

The agent improves itself through:

1. **Quantitative Evaluation**: All outputs scored by graders
2. **Meta-Prompt Optimization**: Underperforming skills automatically improved
3. **Version Control**: All changes tracked with rollback capability
4. **Safety Constraints**: Critical patterns protected from optimization

### Rollback Triggers

Automatic rollback if:
- New version scores 10%+ worse
- 3+ consecutive failures
- Any grader returns < 0.3
- Protected pattern removed

---

## Output Examples

### Intelligence Report

Reports include:
- Executive Summary
- Key Judgments (with confidence)
- Diamond Model Summary
- ATT&CK Mapping
- IOCs (defanged)
- Detection Rules (Sigma/YARA)
- Defensive Recommendations
- Assumptions & Gaps

### Detection Artifacts

- **Sigma Rules**: SIEM detection rules
- **YARA Rules**: File-based detection
- **Hunting Queries**: SPL/KQL queries

### IOC Packages

- **STIX 2.1**: Machine-readable IOC bundles

---

## Configuration

### MCP Servers

Edit `config/mcp_config.json` to configure:
- Server commands and arguments
- API key environment variables
- Rate limits
- Tool selection rules

### Feeds (Fallback)

Edit `config/feeds.json` for RSS fallback when MCP unavailable.

---

## Safety & Trust

### Trust Boundaries

| Source | Trust Level |
|--------|-------------|
| SKILL.md files | Trusted |
| MCP responses | Semi-trusted |
| Feed content | Untrusted |
| User input | Semi-trusted |

### Prime Directives (Immutable)

1. Never fabricate intelligence
2. Calibrate confidence (ICD 203)
3. Preserve analytical integrity
4. Protect sources
5. Fail safe

---

## Roadmap

- [x] Core architecture
- [x] Diamond Model skill
- [x] ACH skill
- [x] Evaluation graders
- [x] Self-evolving loop
- [ ] SecOps SIEM integration
- [ ] SOAR playbook generation
- [ ] Multi-agent collaboration
- [ ] Historical trend analysis

---

## License

MIT License - See LICENSE file.

---

## References

- [Diamond Model of Intrusion Analysis](https://apps.dtic.mil/sti/citations/ADA586960)
- [Psychology of Intelligence Analysis (Heuer)](https://www.cia.gov/resources/csi/books-and-monographs/psychology-of-intelligence-analysis-2/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ICD 203 Analytic Standards](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf)
- [OpenAI Self-Evolving Agents](https://cookbook.openai.com/examples/partners/self_evolving_agents/autonomous_agent_retraining)

---

*Junior Threat Intel Agent v1.0.0*  
*Self-evolving threat intelligence with professional analytical tradecraft*

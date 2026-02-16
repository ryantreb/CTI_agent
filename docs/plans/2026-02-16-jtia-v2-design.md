# JTIA v2.0 Design Document

**Date**: 2026-02-16
**Author**: Ryan Trebilcock + Claude Opus 4.6
**Status**: Approved
**Architecture**: Approach A (Incremental Layering) with planned migration to Hybrid at Phase 5

---

## Executive Summary

JTIA v1.0 is a self-evolving autonomous threat intelligence agent with 3 MCP servers and 7 skills. This design expands it to a comprehensive CTI platform with 23 MCP servers, 18+ skills (including external open-source skill sets), malware analysis capabilities, STIX 2.1 native output, ATT&CK Navigator layer generation, vector-based semantic memory, persistent threat actor profiles, multi-agent collaboration with Devil's Advocate and Verifier agents, and a web dashboard with SIEM integration.

The expansion is phased across 5 releases, each independently usable. The existing SKILL.md prompt-orchestration architecture is preserved as the core differentiator.

---

## Table of Contents

1. [MCP Server Expansion](#1-mcp-server-expansion)
2. [External Skills Integration](#2-external-skills-integration)
3. [STIX 2.1 Native Output](#3-stix-21-native-output)
4. [ATT&CK Navigator Layer Generation](#4-attck-navigator-layer-generation)
5. [Pinecone Vector Memory](#5-pinecone-vector-memory)
6. [Persistent Threat Actor Profiles](#6-persistent-threat-actor-profiles)
7. [Confidence Decay & Re-Evaluation](#7-confidence-decay--re-evaluation)
8. [Multi-Agent Teams (Phase 4)](#8-multi-agent-teams)
9. [Web Dashboard & SIEM Integration (Phase 5)](#9-web-dashboard--siem-integration)
10. [Gap Remediation](#10-gap-remediation)
11. [Phased Roadmap](#11-phased-roadmap)
12. [Success Criteria](#12-success-criteria)

---

## 1. MCP Server Expansion

### Current State (v1.0): 3 servers

| Server | Category |
|--------|----------|
| feedly | Intelligence |
| gti (VirusTotal) | Enrichment |
| fastmcp-threatintel | Enrichment |

### Target State (v2.0): 23 servers (20 new, all open-source)

#### Tier 1 -- Core Intelligence & Enrichment (7 new)

| Server | Repo | What It Adds | API Key |
|--------|------|-------------|---------|
| mcp-shodan | [BurtTheCoder/mcp-shodan](https://github.com/BurtTheCoder/mcp-shodan) | Internet device/vuln data for IPs | Shodan (free tier) |
| otx-mcp | [mrwadams/otx-mcp](https://github.com/mrwadams/otx-mcp) | AlienVault OTX community threat intel | OTX (free) |
| mcp-threatintel | [aplaceforallmystuff/mcp-threatintel](https://github.com/aplaceforallmystuff/mcp-threatintel) | GreyNoise, abuse.ch (Feodo/URLhaus/MalwareBazaar/ThreatFox) | Mixed (most free) |
| ti-mindmap-hub-mcp | [TI-Mindmap-HUB-Org/ti-mindmap-hub-mcp](https://github.com/TI-Mindmap-HUB-Org/ti-mindmap-hub-mcp) | Automated report analysis, STIX 2.1 gen, IOC extraction | None |
| MCP_Security (ORKL) | [fr0gger/MCP_Security](https://github.com/fr0gger/MCP_Security) | Threat reports and actor analysis | None |
| mcp-censys | [nickpending/mcp-censys](https://github.com/nickpending/mcp-censys) | Certificate transparency, attack surface mapping | Censys (free tier) |
| mallory-mcp-server | [malloryai/mallory-mcp-server](https://github.com/malloryai/mallory-mcp-server) | Real-time threat actor, malware, TTPs | Yes |

#### Tier 2 -- Vulnerability Intelligence (5 new)

| Server | Repo | What It Adds | API Key |
|--------|------|-------------|---------|
| mcp-nvd | [marcoeg/mcp-nvd](https://github.com/marcoeg/mcp-nvd) | NIST NVD CVE lookups, CVSS scores | None |
| EPSS-MCP | [jgamblin/EPSS-MCP](https://github.com/jgamblin/EPSS-MCP) | Exploit Prediction Scoring | None |
| kev-mcp | [yeger00/kev-mcp](https://github.com/yeger00/kev-mcp) | CISA Known Exploited Vulns catalog | None |
| vulnerability-intelligence-mcp | [firetix/vulnerability-intelligence-mcp-server](https://github.com/firetix/vulnerability-intelligence-mcp-server) | CVE + EPSS + CVSS + exploit detection | None |
| nuclei-mcp | [addcontent/nuclei-mcp](https://github.com/addcontent/nuclei-mcp) | Active vulnerability scanning, 8000+ templates | None |

#### Tier 3 -- Malware Analysis (5 new)

| Server | Repo | What It Adds | API Key |
|--------|------|-------------|---------|
| GhidraMCP | [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Deep binary decompilation and RE | None |
| YARA-MCP | [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) | Malware signature matching/classification | None |
| Capa-MCP | [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) | Executable capability detection (maps to ATT&CK) | None |
| Radare2-MCP | [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) | Disassembly, decompilation, binary analysis | None |
| Binwalk-MCP | [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub) | Firmware analysis, file extraction, signature scanning | None |

#### Tier 4 -- OSINT & Utility (3 new)

| Server | Repo | What It Adds | API Key |
|--------|------|-------------|---------|
| mcp-dnstwist | [BurtTheCoder/mcp-dnstwist](https://github.com/BurtTheCoder/mcp-dnstwist) | Phishing/typosquatting domain detection | None |
| NetworksDB-MCP | [MorDavid/NetworksDB-MCP](https://github.com/MorDavid/NetworksDB-MCP) | IP/ASN/DNS lookups | None |
| cyberchef-api-mcp | [slouchd/cyberchef-api-mcp-server](https://github.com/slouchd/cyberchef-api-mcp-server) | Data transformation, encoding, hash ops | None |

**Totals**: 23 servers. 100% open-source. 16 require no API key.

### MCP Routing Design

The `enrich-iocs` skill must be updated with routing logic for the expanded server set:

```
IOC Routing Table:
  IP address:
    Primary:   gti.get_ip_address_report()
    Secondary: mcp-shodan.host_lookup()
    Tertiary:  fastmcp-threatintel.analyze()
    Fallback:  mcp-threatintel.lookup() (GreyNoise, AbuseIPDB)

  Domain:
    Primary:   gti.get_domain_report()
    Secondary: mcp-censys.search()
    Tertiary:  mcp-dnstwist.check() (typosquatting variants)
    Fallback:  NetworksDB-MCP.lookup()

  File hash:
    Primary:   gti.get_file_report()
    Secondary: mcp-threatintel.lookup() (MalwareBazaar, ThreatFox)
    Tertiary:  [malware analysis pipeline if sample available]

  URL:
    Primary:   gti.get_url_report()
    Secondary: mcp-threatintel.lookup() (URLhaus)

  CVE:
    Primary:   mcp-nvd.get_cve()
    Secondary: EPSS-MCP.get_score()
    Tertiary:  kev-mcp.check() (is it in CISA KEV?)
    Quaternary: vulnerability-intelligence-mcp.analyze()

  Threat actor:
    Primary:   gti.search_threat_actors()
    Secondary: otx-mcp.get_pulses()
    Tertiary:  MCP_Security.query_orkl()
    Quaternary: mallory-mcp-server.get_actor()
```

**Fallback behavior**: If a server returns an error or is unavailable, log the failure and proceed to the next server in the chain. Never block the pipeline on a single server failure.

---

## 2. External Skills Integration

### Malware Analysis Skills

**Source**: [gl0bal01/malware-analysis-claude-skills](https://github.com/gl0bal01/malware-analysis-claude-skills)

| Skill | Purpose | Integration Point |
|-------|---------|-------------------|
| malware-triage | Rapid initial sample assessment (5-30 min) | After `enrich-iocs` identifies a suspicious file |
| malware-dynamic-analysis | Safe execution and behavior monitoring | When sandbox results are available |
| specialized-file-analyzer | Non-PE formats (.NET, Office, PDF, scripts, ELF) | Based on file type from triage |
| detection-engineer | Detection rule creation and IOC management | Feeds into `generate-report` |
| malware-report-writer | Professional malware analysis reports | Alternative report format for malware-focused sessions |

**Installation**: Clone into `skills/external/malware-analysis/` and reference from AGENT.md.

### YARA Authoring Skills

**Source**: [YARAHQ/yara-rule-skill](https://github.com/YARAHQ/yara-rule-skill)

Provides YARA rule authoring expertise with 20+ automated quality checks (yaraQA), naming conventions, and performance optimization. Complements the YARA-MCP server (which executes rules) by teaching Claude how to write high-quality rules.

**Installation**: Install as `.skill` file per repo instructions.

### Trail of Bits Security Skills

**Source**: [trailofbits/skills](https://github.com/trailofbits/skills)

| Skill | Purpose | Integration Point |
|-------|---------|-------------------|
| variant-analysis | Find similar vulns across codebases using pattern matching | Threat hunting, IOC correlation |
| semgrep-rule-creator | Create custom Semgrep detection rules from observed TTPs | Detection artifact generation |
| static-analysis | CodeQL + Semgrep + SARIF parsing | Code-level vulnerability analysis |
| differential-review | Analyze code changes with security focus | Malware variant diff analysis |
| insecure-defaults | Detect unsafe configs, hardcoded secrets, fail-open patterns | Vulnerability assessments |
| dwarf-expert | DWARF debugging format for binary analysis | Complements GhidraMCP |

**Installation**: Clone relevant skills into `skills/external/trailofbits/`.

### Skill Conflict Resolution

Three sources generate detection rules (JTIA's `generate-report`, gl0bal01's `detection-engineer`, YARAHQ's `yara-rule-skill`). Resolution:

1. **YARA rules**: YARAHQ skill is the primary author. gl0bal01's detection-engineer defers to it. JTIA's generate-report calls the YARAHQ skill rather than generating rules inline.
2. **Sigma rules**: gl0bal01's detection-engineer is the primary author. JTIA's generate-report calls it rather than generating rules inline.
3. **Report generation**: JTIA's `generate-report` remains the primary report skill. gl0bal01's `malware-report-writer` is used only for malware-specific deep-dive reports.

### TI Mindmap HUB Deconfliction

The TI Mindmap HUB MCP server performs Diamond Model analysis and STIX 2.1 generation -- capabilities that overlap with JTIA's core skills. Boundaries:

- **Use TI Mindmap HUB as**: A source of pre-analyzed intelligence, a STIX 2.1 validator, and a CVE intelligence feed
- **Do NOT use it as**: A replacement for JTIA's own Diamond Model or ACH analysis
- **Rationale**: JTIA's analysis skills are the core differentiator. Delegating analysis to an external MCP server reduces the project to a wrapper.

---

## 3. STIX 2.1 Native Output

### New Skill: `produce-stix-bundle`

Transforms Diamond Model analysis output into STIX 2.1 bundles.

**Mapping:**

| Diamond Element | STIX 2.1 Object(s) |
|----------------|---------------------|
| Adversary | `threat-actor` SDO + `intrusion-set` SDO |
| Infrastructure | `infrastructure` SDO + `indicator` SDOs (for IOCs) |
| Capability | `malware` SDO + `attack-pattern` SDOs (from ATT&CK) |
| Victim | `identity` SDO |
| Relationships | `relationship` SROs (uses, targets, indicates, attributed-to) |
| Kill Chain | `kill-chain-phase` embedded in attack-pattern SDOs |

**Indicator Pattern Syntax:**

```
IP:     [ipv4-addr:value = '1.2.3.4']
Domain: [domain-name:value = 'evil.com']
Hash:   [file:hashes.'SHA-256' = 'abc123...']
URL:    [url:value = 'https://evil.com/payload']
```

**Output**: `reports/{guid}_stix_bundle.json`

**Validation**: Use TI Mindmap HUB MCP as a cross-reference to validate STIX bundle structure.

---

## 4. ATT&CK Navigator Layer Generation

### New Skill: `produce-attack-layers`

Auto-generates ATT&CK Navigator layer JSON files from analysis output.

**Layer schema (Navigator v4.5):**

```json
{
  "name": "Campaign X - JTIA Analysis",
  "versions": {"layer": "4.5", "attack": "15"},
  "domain": "enterprise-attack",
  "description": "Auto-generated by JTIA from Diamond Model analysis",
  "techniques": [
    {
      "techniqueID": "T1566.001",
      "tactic": "initial-access",
      "color": "#ff6666",
      "comment": "Spearphishing attachment observed in delivery phase",
      "score": 85,
      "metadata": [
        {"name": "confidence", "value": "high"},
        {"name": "source", "value": "GTI file analysis"}
      ]
    }
  ]
}
```

**Color coding by confidence:**

| Confidence | Color | Hex |
|-----------|-------|-----|
| Confirmed/observed | Red | #ff6666 |
| Likely (enrichment-based) | Orange | #ffaa66 |
| Possible (low confidence) | Yellow | #ffff66 |

**Integration**: Capa-MCP output maps directly to ATT&CK techniques, automatically feeding the Navigator layer from malware analysis.

**Output**: `reports/{guid}_attack_layer.json`

---

## 5. Pinecone Vector Memory

### Architecture

Use the existing Pinecone MCP server connection to create a semantic search layer across all historical intelligence.

**Index configuration:**

| Setting | Value |
|---------|-------|
| Index name | `jtia-intel-memory` |
| Embedding model | `multilingual-e5-large` |
| Cloud/Region | aws / us-east-1 |
| Field map | `text` |

**Record schema:**

```json
{
  "_id": "report-{guid}",
  "text": "Executive summary + key judgments text",
  "report_type": "tactical|operational|strategic",
  "threat_actors": ["APT29", "FIN7"],
  "ttps": ["T1566.001", "T1059.001"],
  "ioc_types": ["hash", "domain", "ip"],
  "date": "2026-02-16",
  "confidence": 0.85,
  "campaign": "Campaign Name"
}
```

### New Skill: `recall-intelligence`

Queries Pinecone before new analysis to surface relevant historical context.

**Use cases:**
- "Find campaigns with similar TTPs to this cluster"
- "What do we know about infrastructure overlapping with this IP range?"
- "Historical context for this threat actor's evolution"
- Cross-session recall during `plan-session` skill

**Integration**: Called at the start of `diamond-model-analysis` to pre-load historical context. Also called during `plan-session` to inform priority decisions.

---

## 6. Persistent Threat Actor Profiles

### Directory Structure

```
actors/
  apt29.json
  fin7.json
  lazarus-group.json
  ...
```

### Profile Schema

```json
{
  "actor_id": "APT29",
  "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
  "attribution_confidence": "likely",
  "motivation": "espionage",
  "nation_state": "Russia",
  "first_tracked": "2026-02-16",
  "last_updated": "2026-02-16",
  "known_ttps": [
    {"technique": "T1566.001", "confidence": "high", "sources": ["report-abc"], "first_observed": "..."}
  ],
  "known_infrastructure": [
    {"type": "domain", "value": "example[.]com", "first_seen": "...", "last_seen": "...", "status": "active|inactive"}
  ],
  "known_malware": ["SUNBURST", "WellMess", "EnvyScout"],
  "targeting": {
    "sectors": ["government", "technology", "think-tanks"],
    "geographies": ["US", "EU", "NATO members"]
  },
  "reports": ["report-abc", "report-def"],
  "assessment_history": [
    {"date": "2026-02-16", "assessment": "Active espionage campaign targeting...", "confidence": "likely"}
  ]
}
```

### Integration

- `diamond-model-analysis` checks `actors/` during Adversary vertex population
- New intelligence automatically enriches existing profiles
- Profiles are also upserted to Pinecone for semantic search
- Confidence decay (Section 7) applies to actor profile assessments

---

## 7. Confidence Decay & Re-Evaluation

### Decay Formula

```
current_confidence = original_confidence * decay_factor
decay_factor = max(0.1, 1 - (days_since_last_verified / half_life_days))
```

### Half-Life by Type

| IOC/Assessment Type | Half-Life (days) | Rationale |
|--------------------|-----------------|-----------|
| IP address | 30 | Infrastructure rotates fast |
| Domain | 90 | Domains persist longer |
| File hash | 365 | Hashes are immutable |
| URL | 14 | URLs are ephemeral |
| TTP mapping | 730 | TTPs change slowly |
| Actor profile | 365 | Need periodic re-assessment |

### State File: `state/confidence_tracker.json`

```json
{
  "tracked_items": [
    {
      "item_id": "ioc-abc123",
      "type": "ip",
      "value": "1.2.3.4",
      "original_confidence": 0.85,
      "last_verified": "2026-02-16T12:00:00Z",
      "half_life_days": 30,
      "current_confidence": 0.72,
      "decay_status": "active|stale|expired"
    }
  ]
}
```

### Re-Evaluation Triggers

- IOC confidence decays below 0.3: queue for re-enrichment
- Actor profile not updated in 90 days: flag for review
- Session start: scan confidence_tracker.json for stale items
- Re-enrichment uses the same MCP routing table from Section 1

---

## 8. Multi-Agent Teams

### Phase 4 Team Composition (5 agents)

| Agent | Role | Skills Used | Mandate |
|-------|------|------------|---------|
| **Collector** | Gather raw intelligence | monitor-feeds, enrich-iocs | Parallel feed monitoring and IOC enrichment across all MCP servers |
| **Analyst** | Produce assessments | diamond-model, ACH, malware-analysis skills | Structure analysis and generate hypotheses |
| **Devil's Advocate** | Challenge assessments | ACH (adversarial mode) | Systematically argue against the Analyst's leading hypothesis |
| **Verifier** | Validate all claims | verify-claims, variant-analysis | Independent fact-checking of ALL claims before report generation |
| **Reporter** | Produce final products | generate-report, produce-stix-bundle, produce-attack-layers | Assemble verified, challenged intelligence into final deliverables |

### Workflow

```
Collector --> Analyst --> [Devil's Advocate <-> Analyst debate] --> Verifier --> Reporter
                                     |
                           (iterate until consensus
                            or disagreement documented)
```

### Devil's Advocate Protocol

1. Receives Analyst's assessment + evidence matrix
2. MUST argue for the second-most-likely hypothesis
3. Identifies evidence the Analyst underweighted
4. Proposes at least one alternative interpretation per key judgment
5. Challenges any assessment rated "highly likely" or above -- forces Analyst to justify
6. Output: Dissenting analysis with specific counter-evidence
7. Disagreements documented in report's "Alternative Analysis" section (per ICD 203)

### Verifier Protocol

1. Receives the debate output (both Analyst and Devil's Advocate positions)
2. Independently re-queries all cited sources via MCP servers
3. Confirms every IOC, TTP, and attribution claim exists in the source data
4. Flags any claim that cannot be independently verified
5. Output: Verified claims feed + list of unverifiable/hallucinated claims
6. Reporter only receives Verifier-approved content

### Rationale

Addresses two critical LLM failure modes:
- **Confirmation bias**: LLMs reinforce their initial framing. The Devil's Advocate has a structural mandate to challenge.
- **Hallucination**: Fabricating plausible-sounding IOCs/claims. The Verifier independently validates every claim against source APIs.

---

## 9. Web Dashboard & SIEM Integration

### Phase 5 (Approach C Migration)

At Phase 5, add a thin Python service layer (FastAPI) alongside the existing SKILL.md architecture.

**Dashboard features:**
- Report viewer (rendered markdown)
- ATT&CK Navigator layer viewer (embedded iframe)
- STIX 2.1 relationship graph visualization (D3.js)
- MCP server health status
- Confidence decay tracker
- Actor profile browser
- Session history and metrics

**SIEM integration:**
- Elastic Security MCP server for pushing detection rules and searching events
- Sigma rule auto-deployment to configured SIEM
- IOC list export in SIEM-native formats

**Database**: SQLite for development, Postgres for production. ORM via SQLAlchemy.

**This section is intentionally lighter** -- detailed design deferred until Phases 1-4 are stable and the migration decision is confirmed.

---

## 10. Gap Remediation

### Gap 1: Git Version Control

**Action**: Initialize git repository immediately.

```
git init
git add .
git commit -m "JTIA v1.0.0 - Initial commit"
```

**Branching strategy:**
- `main`: Stable releases (tagged with version)
- `develop`: Integration branch for in-progress phases
- `phase-N/*`: Feature branches for each phase
- Merge via PR with self-review

### Gap 2: Testing Strategy

**Unit tests** (Python, in `tests/`):
- MCP server health checks
- JSON schema validation for all state files
- IOC defanging/refanging correctness
- Confidence decay calculation accuracy

**Integration tests:**
- Full pipeline with mock MCP responses (demo mode -- see Gap 14)
- Skill regression: run all 4 graders against known-good inputs after any skill change
- External skill compatibility: verify gl0bal01, YARAHQ, and ToB skills load and execute correctly

**Evaluation tests** (existing graders):
- Run on every commit via CI (see Gap 8)
- Threshold enforcement: fail CI if any grader drops below threshold

### Gap 3: API Key Management

**Tiered key requirements:**

| Tier | Keys Required | Keys Optional |
|------|--------------|---------------|
| Tier 1 (Core Intel) | FEEDLY_ACCESS_TOKEN, VT_API_KEY | SHODAN_API_KEY, CENSYS_API_KEY, OTX_API_KEY, MALLORY_API_KEY |
| Tier 2 (Vuln Intel) | None | None (all public APIs) |
| Tier 3 (Malware) | None | None (all local tools) |
| Tier 4 (OSINT) | None | None (all local/public) |

**Graceful degradation:**
- New skill `check-server-health` runs at session start
- Reports available vs unavailable servers
- Adjusts routing table to skip unavailable servers
- Logs degraded capability so user knows what's missing

**Updated `.env.template`:**

```bash
# === REQUIRED ===
FEEDLY_ACCESS_TOKEN=
VT_API_KEY=

# === TIER 1 OPTIONAL (Enhanced Enrichment) ===
SHODAN_API_KEY=
CENSYS_API_KEY=
OTX_API_KEY=
MALLORY_API_KEY=

# === TIER 2-4: No API keys required ===
# All vulnerability, malware analysis, OSINT, and utility servers
# use public APIs or local tools.
```

### Gap 4: MCP Routing Design

Addressed in Section 1 (MCP Routing Table). The `enrich-iocs` skill must be refactored from hardcoded GTI/fastmcp routing to the dynamic routing table with fallback chains.

### Gap 5: Skill Conflict Resolution

Addressed in Section 2 (Skill Conflict Resolution). Clear ownership: YARAHQ owns YARA, gl0bal01's detection-engineer owns Sigma, JTIA's generate-report orchestrates but delegates.

### Gap 6: OPSEC Considerations

**Rate limiting:**

| Server | Limit | Strategy |
|--------|-------|----------|
| GTI (VirusTotal) | 1000/day | Queue overflow for next session |
| Shodan | 100/month (free) | Reserve for high-priority IPs |
| AbuseIPDB | 1000/day | Prioritize high-confidence IOCs |
| Censys | 250/month (free) | Reserve for certificate/ASM queries |
| NVD | 50/rolling 30s window | Built-in rate limiter |
| All others | Varies | Document in mcp_config.json per server |

**Data exposure awareness:**
- Every MCP query sends data to a third party
- Document which servers receive which data types in `config/data_flow.md`
- For sensitive investigations, support a "local-only" mode using only Tier 3 (malware analysis) servers that run locally

**Proxy support:**
- Add optional `HTTP_PROXY`/`HTTPS_PROXY` env vars to `.env.template`
- Defer Tor routing to user configuration (not in scope for v2.0)

### Gap 7: Open-Source Documentation

**New files:**

| File | Purpose |
|------|---------|
| `CONTRIBUTING.md` | How to contribute: add servers, add skills, submit PRs |
| `docs/architecture.md` | System architecture diagram and data flow |
| `docs/adding-mcp-server.md` | Step-by-step guide to adding a new MCP server |
| `docs/adding-skill.md` | Step-by-step guide to adding a new skill |
| `LICENSE` | MIT License (already referenced in README) |

### Gap 8: CI/CD Pipeline

**GitHub Actions workflows:**

| Workflow | Trigger | Checks |
|----------|---------|--------|
| `lint.yml` | Every push | JSON schema validation for all config/state files, markdown lint for SKILL.md files |
| `test.yml` | Every push | Python unit tests, evaluation graders against sample data |
| `integration.yml` | PR to main | Full pipeline with mock MCP responses (demo mode) |

### Gap 9: Missing `plan-session` Skill

Create `skills/plan-session/SKILL.md` with:
- Session priority determination based on user input and stale items
- MCP server health check integration
- Historical context loading from Pinecone
- Execution plan generation with dependency ordering

### Gap 10: Offline/Air-Gapped Mode

**Capabilities by connectivity:**

| Mode | Available Capabilities |
|------|----------------------|
| **Full online** | All 23 MCP servers, all skills |
| **Partial online** | Tier 2-4 servers (no commercial API keys), all skills |
| **Local only** | Tier 3 malware analysis (Ghidra, YARA, Capa, Radare2, Binwalk) + CyberChef + all analysis/reporting skills |
| **Air-gapped** | All SKILL.md-based analysis (Diamond Model, ACH, report generation) + cached data only |

**Implementation**: `plan-session` skill detects connectivity at session start and adjusts execution plan accordingly.

### Gap 11: Structured Logging & Observability

**Unified log schema:**

```json
{
  "timestamp": "ISO8601",
  "session_id": "uuid",
  "skill": "skill_name",
  "event_type": "mcp_call|enrichment|analysis|error|metric",
  "severity": "info|warn|error|critical",
  "data": {
    "mcp_server": "server_name",
    "ioc_type": "hash|ip|domain",
    "response_time_ms": 250,
    "result_summary": "..."
  }
}
```

**Metrics collection:**
- IOCs enriched per session
- Average confidence scores over time
- MCP server response times and error rates
- Grader scores trend
- Stored in `state/metrics.jsonl`

**Session replay**: Sequential log entries with session_id enable full reconstruction of any past session's decision chain.

### Gap 12: Error Taxonomy

| Error Class | Examples | Recovery Strategy |
|-------------|---------|-------------------|
| `TRANSIENT` | Rate limit (429), timeout, 5xx | Exponential backoff, max 3 retries |
| `AUTH` | 401/403, invalid API key | Log, skip server, alert user |
| `NOT_FOUND` | 404, resource doesn't exist | Mark claim as REFUTED if existence asserted |
| `PARSE` | Malformed JSON, unexpected schema | Log raw response, mark UNVERIFIED |
| `UNAVAILABLE` | Server down, DNS failure | Skip server, use fallback in routing table |
| `STATE_CORRUPTION` | JSON parse error on state file | Halt, alert user, attempt backup restore |
| `SKILL_FAILURE` | Skill execution error | Log, skip skill, continue pipeline |

### Gap 13: TI Mindmap HUB Deconfliction

Addressed in Section 2 (TI Mindmap HUB Deconfliction).

### Gap 14: Sample/Demo Dataset

**Create `demo/` directory:**

| File | Purpose |
|------|---------|
| `demo/sample_input.json` | Sanitized real threat report (or synthetic) with IOCs, TTPs, actor references |
| `demo/mock_mcp_responses/` | Cached responses from each MCP server for the sample input |
| `demo/expected_output/` | Expected report, STIX bundle, ATT&CK layer at each pipeline stage |
| `demo/run_demo.sh` | Script that runs the full pipeline in demo mode using mock responses |

**Demo mode activation**: Set `JTIA_DEMO_MODE=true` in environment. Skills use mock MCP responses instead of live API calls.

### Gap 15: Versioning Strategy

**Semantic versioning (semver):**

| Change Type | Version Bump | Example |
|-------------|-------------|---------|
| Phase completion | Minor | v2.1.0 (Phase 1), v2.2.0 (Phase 2) |
| Bug fix or skill refinement | Patch | v2.1.1 |
| Breaking change (architecture migration) | Major | v3.0.0 (if Approach C migration changes interfaces) |

**Git tags**: `v2.1.0`, `v2.2.0`, etc. Tagged on merge to `main`.

**Phase-to-version mapping:**

| Phase | Version |
|-------|---------|
| Phase 1 (MCP expansion) | v2.1.0 |
| Phase 2 (STIX + skills) | v2.2.0 |
| Phase 3 (memory + profiles) | v2.3.0 |
| Phase 4 (multi-agent) | v2.4.0 |
| Phase 5 (dashboard + SIEM) | v3.0.0 |

### Gap 16: Project CLAUDE.md

Create `/home/ryantreb/Security Projects/CTI_agent/CLAUDE.md` with:
- Project description and architecture overview
- Development conventions (SKILL.md format, JSON schema standards)
- How to test changes (run graders, demo mode)
- Git workflow (branch naming, PR process)
- Distinction from AGENT.md (CLAUDE.md = development instructions, AGENT.md = runtime brain)

---

## 11. Phased Roadmap

| Phase | Contents | New Servers | New Skills | Estimated Effort | Dependencies |
|-------|----------|-------------|------------|-----------------|-------------|
| **1** | MCP server expansion + routing redesign + API key management + git init + CI/CD | 20 new | check-server-health, plan-session (missing) | Medium | API keys for Tier 1 optional servers |
| **2** | STIX 2.1 output + ATT&CK Navigator layers + external skills (gl0bal01, YARAHQ, ToB) + demo dataset | 0 | produce-stix-bundle, produce-attack-layers + 11 external | Medium-High | Phase 1 MCP servers working |
| **3** | Pinecone vector memory + persistent actor profiles + confidence decay + structured logging | 0 | recall-intelligence | Medium | Pinecone index created |
| **4** | Multi-agent teams (Collector, Analyst, Devil's Advocate, Verifier, Reporter) + detection validation | 0 | Agent team orchestration | High | Phases 1-3 stable |
| **5** | Web dashboard + SIEM/SOAR integration + Python service layer (Approach C migration) | Elastic Security MCP | Dashboard, SIEM push | High | Phase 4 stable |

**Each phase produces independently usable capabilities.** You can demo after any phase.

---

## 12. Success Criteria

### Phase 1 Success

- [ ] All 23 MCP servers configured in `mcp_config.json`
- [ ] `enrich-iocs` skill uses dynamic routing table with fallback
- [ ] `check-server-health` skill reports server availability at session start
- [ ] Graceful degradation when optional API keys are missing
- [ ] Git repository initialized with branching strategy
- [ ] CI pipeline runs on every push

### Phase 2 Success

- [ ] STIX 2.1 bundles generated for every report
- [ ] ATT&CK Navigator layers generated with confidence-based coloring
- [ ] External skills (gl0bal01, YARAHQ, ToB) installed and integrated
- [ ] Skill conflict resolution working (YARA via YARAHQ, Sigma via gl0bal01)
- [ ] Demo mode works end-to-end with mock data

### Phase 3 Success

- [ ] Pinecone index created and populated with historical reports
- [ ] `recall-intelligence` skill surfaces relevant context during analysis
- [ ] Actor profiles accumulate across sessions
- [ ] Confidence decay triggers re-enrichment for stale IOCs
- [ ] Structured logging captures all events with unified schema

### Phase 4 Success

- [ ] 5-agent team executes full pipeline
- [ ] Devil's Advocate challenges every "highly likely" or above assessment
- [ ] Verifier independently validates all claims before report generation
- [ ] Disagreements documented in "Alternative Analysis" report section
- [ ] No hallucinated IOCs pass through to final report

### Phase 5 Success

- [ ] Web dashboard renders reports, ATT&CK layers, STIX graphs
- [ ] SIEM integration pushes Sigma rules to Elastic
- [ ] Python service layer handles state management and scheduling
- [ ] Full system operable by someone other than the author (open-source ready)

---

## References

- [Diamond Model of Intrusion Analysis](https://apps.dtic.mil/sti/citations/ADA586960)
- [Psychology of Intelligence Analysis (Heuer)](https://www.cia.gov/resources/csi/books-and-monographs/psychology-of-intelligence-analysis-2/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ICD 203 Analytic Standards](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [awesome-cyber-security-mcp](https://github.com/format81/awesome-cyber-security-mcp)
- [FuzzingLabs MCP Security Hub](https://github.com/FuzzingLabs/mcp-security-hub)
- [gl0bal01/malware-analysis-claude-skills](https://github.com/gl0bal01/malware-analysis-claude-skills)
- [YARAHQ/yara-rule-skill](https://github.com/YARAHQ/yara-rule-skill)
- [trailofbits/skills](https://github.com/trailofbits/skills)

---

*JTIA v2.0 Design Document -- 2026-02-16*
*Approved for implementation via phased roadmap.*

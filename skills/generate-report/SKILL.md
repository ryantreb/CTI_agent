---
name: generate-report
description: Produce professional intelligence products from analyzed data. Use after Diamond Model and ACH analysis to create tactical reports, detection artifacts, and strategic assessments. Formats output per intelligence community standards.
---

# Generate Report Skill

## Purpose
Transform analytical outputs into actionable intelligence products calibrated to audience needs.

## Report Types

| Type | Audience | Timeframe | Focus |
|------|----------|-----------|-------|
| Tactical | SOC/IR | Immediate | IOCs, detection rules |
| Operational | Security teams | Days-weeks | TTPs, hunting guidance |
| Strategic | Leadership | Months | Trends, risk, investment |

## Report Template

See `references/report_template.md` for full template.

### Required Sections

1. **Classification Header** — TLP, confidence, validity period
2. **Executive Summary** — 2-3 sentences: what, who, significance
3. **Key Judgments** — Numbered, with confidence levels
4. **Diamond Model Summary** — Table of elements with confidence
5. **Kill Chain / ATT&CK Mapping** — Phase-technique-evidence table
6. **ACH Summary** (if attribution assessed) — Hypothesis ranking
7. **Indicators of Compromise** — Structured IOC tables
8. **Defensive Recommendations** — Prioritized actions
9. **Key Assumptions** — What we're assuming is true
10. **Intelligence Gaps** — What we don't know
11. **Reassessment Triggers** — When to update
12. **Sources** — With reliability assessment

## Confidence Language (MANDATORY)

All judgments MUST use ICD 203 probability language:

| Confidence | Probability | Phrasing |
|------------|-------------|----------|
| Almost certain | >95% | "We assess with high confidence..." |
| Highly likely | 80-95% | "We assess it is highly likely..." |
| Likely | 60-80% | "We assess it is likely..." |
| Roughly even | 40-60% | "We cannot determine with confidence..." |
| Unlikely | 20-40% | "We assess it is unlikely..." |

**NEVER**: "We believe", "We think", "Probably" without calibration

## IOC Formatting

### Network Indicators Table
```markdown
| Type | Value | First Seen | Last Seen | Context | Confidence |
|------|-------|------------|-----------|---------|------------|
| Domain | evil[.]com | 2025-01-01 | 2025-01-10 | C2 server | High |
| IP | 192[.]168[.]1[.]1 | 2025-01-05 | Active | Payload host | Medium |
```

### File Indicators Table
```markdown
| SHA256 | MD5 | Filename | Malware Family | Confidence |
|--------|-----|----------|----------------|------------|
| abc123... | def456... | payload.dll | SUNBURST | High |
```

**Defanging Rules:**
- Domains: `evil[.]com`
- IPs: `192[.]168[.]1[.]1`
- URLs: `hxxps://evil[.]com/path`

## Detection Artifact Generation

### Sigma Rule Template
```yaml
title: [Threat Name] - [Detection Description]
id: [UUID]
status: experimental
description: Detects [specific behavior] associated with [threat]
references:
    - [Source URL]
author: CTI Agent
date: [YYYY/MM/DD]
tags:
    - attack.[tactic]
    - attack.[technique_id]
logsource:
    category: [category]
    product: [product]
detection:
    selection:
        [field]: [value]
    condition: selection
falsepositives:
    - [Known FP scenarios]
level: [informational|low|medium|high|critical]
```

### YARA Rule Template
```yara
rule [Threat_Name]_[Variant] {
    meta:
        description = "[Description]"
        author = "CTI Agent"
        date = "[YYYY-MM-DD]"
        reference = "[Source]"
        tlp = "[WHITE|GREEN|AMBER|RED]"
        
    strings:
        $s1 = "[string1]"
        $s2 = { [hex bytes] }
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        any of them
}
```

## Detection Rule Delegation

When generating detection artifacts, delegate to specialized skills:

| Rule Type | Delegate To | Rationale |
|-----------|------------|-----------|
| YARA rules | `external/yara-rule-skill` | YARAHQ provides 20+ quality checks, naming conventions, performance optimization |
| Sigma rules | `external/malware-analysis/detection-engineer` | gl0bal01 provides IOC management and multi-format conversion |
| Suricata rules | `external/malware-analysis/detection-engineer` | Same skill handles network detection rules |

**Protocol**: Generate detection artifacts by invoking the specialized skill with the analysis context, rather than writing rules inline. This ensures professional quality and consistency.

See `config/skill_ownership.json` for the full ownership matrix.

## Output Files

| File | Format | Content |
|------|--------|---------|
| `{guid}.md` | Markdown | Full intelligence report |
| `{guid}_iocs.json` | STIX 2.1 | Machine-readable IOCs |
| `{guid}_sigma.yml` | Sigma | Detection rules |
| `{guid}_yara.yar` | YARA | File detection rules |

## Quality Checklist

Before finalizing report:

- [ ] Every judgment has confidence level
- [ ] All IOCs are defanged
- [ ] ATT&CK techniques have IDs (not just names)
- [ ] Sources are cited with reliability
- [ ] Assumptions are explicitly stated
- [ ] At least 3 defensive recommendations
- [ ] Intelligence gaps acknowledged
- [ ] No fabricated or unverified claims

## File Output Location

Final reports go to: `reports/{guid}.md`

Detection artifacts go to: `reports/{guid}_detections/`

For user delivery, copy to: `/mnt/user-data/outputs/`

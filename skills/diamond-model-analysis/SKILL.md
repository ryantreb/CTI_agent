---
name: diamond-model-analysis
description: Structure intrusion analysis using the Diamond Model framework (Adversary, Infrastructure, Capability, Victim). Use when analyzing threats to identify relationships, pivot between data points, and build activity threads. Essential for professional-grade threat analysis.
---

# Diamond Model Analysis Skill

## Purpose
Apply the Diamond Model of Intrusion Analysis to structure threat data, identify relationships, and enable analytical pivoting between Adversary, Infrastructure, Capability, and Victim.

## Diamond Model Core Elements

```
           Adversary
              /\
             /  \
            /    \
           /      \
    Capability ─── Infrastructure
            \      /
             \    /
              \  /
             Victim
```

### Element Definitions

| Element | Description | Data Sources |
|---------|-------------|--------------|
| **Adversary** | Actor identity, motivation, resources | GTI threat actors, attribution reports |
| **Infrastructure** | C2 servers, domains, IPs, hosting | IOC enrichment, passive DNS, WHOIS |
| **Capability** | Malware, exploits, TTPs | File analysis, sandbox, ATT&CK mapping |
| **Victim** | Target org, sector, geography | Feed context, targeting patterns |

### Meta-Features

| Feature | Description | Required |
|---------|-------------|----------|
| Timestamp | Date/time of event | Yes |
| Phase | Kill Chain stage | Yes |
| Result | Success/failure/unknown | If known |
| Direction | Attack flow direction | Yes |
| Methodology | Specific techniques | Yes |

## Analysis Protocol

### Step 1: Initialize Diamond Event
```json
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "phase": "reconnaissance|weaponization|delivery|exploitation|installation|c2|actions",
  "diamond": {
    "adversary": {
      "name": null,
      "aliases": [],
      "motivation": "espionage|financial|hacktivism|destruction|unknown",
      "attribution_confidence": 0.0
    },
    "infrastructure": {
      "domains": [],
      "ips": [],
      "urls": [],
      "c2_servers": [],
      "hosting_providers": []
    },
    "capability": {
      "malware_families": [],
      "exploits": [],
      "ttps": [],
      "tools": []
    },
    "victim": {
      "sector": null,
      "geography": null,
      "organization": null,
      "targeting_rationale": null
    }
  }
}
```

### Step 2: Populate via MCP Enrichment

```
FOR EACH data_point IN raw_intelligence:

  IF data_point IS ip/domain/url:
    CALL gti.get_*_report()
    ADD TO infrastructure
    CALL gti.get_entities_related_to_*()
    EXTRACT capability links (communicating_files)
    
  IF data_point IS file_hash:
    CALL gti.get_file_report()
    ADD TO capability.malware_families
    CALL gti.get_file_behavior_summary()
    EXTRACT infrastructure (contacted_domains, contacted_ips)
    
  IF threat_actor mentioned:
    CALL gti.search_threat_actors()
    ADD TO adversary
    CALL gti.get_collection_timeline_events()
    EXTRACT historical patterns
```

### Step 3: Analytical Pivoting

Six pivot directions enable hypothesis generation:

| From → To | Question Answered |
|-----------|-------------------|
| Infrastructure → Capability | What malware uses this C2? |
| Capability → Infrastructure | What infrastructure does this malware use? |
| Adversary → Capability | What TTPs does this actor prefer? |
| Capability → Adversary | Who uses this specific technique? |
| Infrastructure → Adversary | Who controls this infrastructure? |
| Victim → Adversary | Who targets this sector/geography? |

### Step 4: Activity Threading

Group related Diamond Events by Kill Chain phase:

```
Activity Thread: {campaign_name}
├── Event 1 (Reconnaissance): Diamond{adversary: ?, capability: scanning}
├── Event 2 (Delivery): Diamond{capability: phishing, infrastructure: domain.com}
├── Event 3 (Exploitation): Diamond{capability: CVE-2024-XXXX}
├── Event 4 (Installation): Diamond{capability: backdoor.exe}
├── Event 5 (C2): Diamond{infrastructure: c2.evil.com}
└── Event 6 (Actions): Diamond{victim: Target Corp, capability: exfiltration}
```

## Kill Chain Phase Mapping

| Phase | Typical Diamond Focus |
|-------|----------------------|
| Reconnaissance | Victim + Infrastructure (scanning sources) |
| Weaponization | Capability (malware creation) |
| Delivery | Infrastructure + Capability (delivery mechanism) |
| Exploitation | Capability (exploit/vulnerability) |
| Installation | Capability (persistence mechanism) |
| C2 | Infrastructure (C2 servers) |
| Actions on Objectives | Victim + Capability (impact) |

## Output Schema

```json
{
  "analysis_type": "diamond_model",
  "thread_id": "uuid",
  "thread_name": "descriptive_campaign_name",
  "events": [
    {
      "event_id": "uuid",
      "phase": "c2",
      "diamond": { /* populated elements */ }
    }
  ],
  "relationships": [
    {
      "from": {"element": "infrastructure", "value": "evil.com"},
      "to": {"element": "capability", "value": "SUNBURST"},
      "relationship": "hosts_c2_for",
      "confidence": 0.85
    }
  ],
  "intelligence_gaps": [
    "Adversary attribution incomplete - only infrastructure confirmed",
    "Victim targeting rationale unclear"
  ],
  "recommended_pivots": [
    "Query passive DNS for evil.com subdomains",
    "Search for SUNBURST hash variants in GTI"
  ],
  "confidence_summary": {
    "adversary": 0.4,
    "infrastructure": 0.9,
    "capability": 0.85,
    "victim": 0.7
  }
}
```

## Integration with ATT&CK

Map each Capability element to MITRE ATT&CK:

```
capability.ttps: [
  {
    "technique_id": "T1566.001",
    "technique_name": "Spearphishing Attachment",
    "tactic": "Initial Access",
    "evidence": "Malicious DOCX observed in delivery phase"
  }
]
```

Prefer sub-technique (T1566.001) over technique (T1566) over tactic (Initial Access).

## Handoff to ACH

Diamond Model structures WHAT happened. For WHO/WHY questions (attribution), hand off to `analysis-competing-hypotheses`:

```
Diamond Output → Evidence for ACH Matrix
  - Infrastructure ownership → supports/refutes actor hypotheses
  - Capability signatures → supports/refutes actor hypotheses
  - Victim targeting → supports/refutes motivation hypotheses
```

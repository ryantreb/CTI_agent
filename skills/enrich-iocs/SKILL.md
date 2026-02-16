---
name: enrich-iocs
description: Multi-source IOC enrichment using GTI and fastmcp-threatintel MCP servers. Use when IOCs need context, reputation data, or behavioral analysis. Orchestrates queries across multiple enrichment sources.
---

# Enrich IOCs Skill

## Purpose
Transform raw IOCs into enriched intelligence with reputation, relationships, and behavioral context from multiple sources.

## Enrichment Matrix

| IOC Type | Primary MCP | Secondary MCP | Key Tools |
|----------|-------------|---------------|-----------|
| File Hash | gti | fastmcp-threatintel | get_file_report, get_file_behavior_summary |
| Domain | gti | feedly | get_domain_report, get_entities_related_to_a_domain |
| IP Address | fastmcp-threatintel | gti | analyze, get_ip_address_report |
| URL | gti | — | get_url_report |
| CVE | feedly | gti | get_cve_details, search_vulnerabilities |

## Enrichment Protocols

### File Hash Enrichment
```
1. CALL gti.get_file_report(hash)
   EXTRACT: detection_ratio, first_seen, threat_labels, file_type
   
2. IF detection_ratio > 0.3:
   CALL gti.get_file_behavior_summary(hash)
   EXTRACT: contacted_domains, contacted_ips, dropped_files, registry_keys
   
3. CALL gti.get_entities_related_to_a_file(hash, "contacted_domains")
   EXTRACT: C2 infrastructure relationships
   
4. IF threat_label identified:
   CALL feedly.search_malware_family(threat_label)
   EXTRACT: related_campaigns, threat_actors, ttps
```

### Domain Enrichment
```
1. CALL gti.get_domain_report(domain)
   EXTRACT: reputation, categories, whois, dns_records
   
2. CALL gti.get_entities_related_to_a_domain(domain, "communicating_files")
   EXTRACT: associated malware hashes
   
3. CALL gti.get_entities_related_to_a_domain(domain, "resolutions")
   EXTRACT: historical IP resolutions
```

### IP Address Enrichment
```
1. CALL fastmcp-threatintel.analyze(ip)
   EXTRACT: vt_score, abuseipdb_score, ipinfo_data
   
2. CALL gti.get_ip_address_report(ip)
   EXTRACT: reputation, asn, country, communicating_files
```

## Confidence Calculation

```python
confidence = (
  0.25 × gti_detection_ratio +      # VT detections / total engines
  0.25 × source_corroboration +     # Multiple sources agree (0-1)
  0.20 × behavioral_indicators +    # Sandbox results present (0-1)
  0.15 × temporal_relevance +       # Recency factor (0-1)
  0.15 × attribution_strength       # APT link confidence (0-1)
)
```

### Temporal Relevance Decay
```
days_old = (now - first_seen).days
temporal_relevance = max(0, 1 - (days_old / 365))
```

## Output Schema

```json
{
  "enrichment_id": "uuid",
  "timestamp": "ISO8601",
  "ioc": {
    "type": "hash|domain|ip|url|cve",
    "value": "...",
    "original_source": "feed_guid"
  },
  "enrichment": {
    "gti": {
      "detection_ratio": 0.45,
      "threat_labels": ["trojan", "banker"],
      "first_seen": "ISO8601",
      "relationships": {}
    },
    "fastmcp": {
      "abuseipdb_score": 85,
      "vt_score": 12
    },
    "feedly": {
      "threat_actors": ["FIN7"],
      "campaigns": ["Campaign Name"]
    }
  },
  "confidence": 0.75,
  "confidence_factors": {
    "detection_ratio": 0.45,
    "source_corroboration": 0.8,
    "behavioral_indicators": 0.9,
    "temporal_relevance": 0.7,
    "attribution_strength": 0.6
  },
  "ttps_extracted": ["T1059.001", "T1071.001"],
  "recommended_actions": [
    "Block at perimeter",
    "Hunt for related hashes"
  ]
}
```

## Rate Limiting

| Source | Free Tier Limit | Strategy |
|--------|-----------------|----------|
| GTI (VirusTotal) | 1000/day | Queue overflow for next session |
| AbuseIPDB | 1000/day | Prioritize high-confidence IOCs |
| IPinfo | 50000/month | No limit concerns |

## Cross-Validation Rules

- IOC flagged malicious by 2+ sources: **High confidence**
- IOC flagged by 1 source only: **Medium confidence**, note in gaps
- Contradictory results: **Low confidence**, flag for manual review

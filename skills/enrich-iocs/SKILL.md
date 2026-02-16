---
name: enrich-iocs
description: Multi-source IOC enrichment using dynamic routing across 23 MCP servers. Orchestrates queries through primary/secondary/fallback chains with graceful degradation when servers are unavailable.
---

# Enrich IOCs Skill

## Purpose
Transform raw IOCs into enriched intelligence with reputation, relationships, and behavioral context from multiple sources using dynamic routing.

## Enrichment Routing (Dynamic)

Routing is determined by `config/mcp_server_registry.json`. The `check-server-health` skill adjusts routes at session start based on available servers.

### Default Routing Table

| IOC Type | Primary | Secondary | Fallback |
|----------|---------|-----------|----------|
| File Hash | gti | mcp-threatintel | — |
| Domain | gti | mcp-censys, mcp-dnstwist | networksdb-mcp |
| IP Address | gti, mcp-shodan | fastmcp-threatintel, mcp-threatintel | networksdb-mcp |
| URL | gti | mcp-threatintel | — |
| CVE | mcp-nvd | epss-mcp, kev-mcp | vulnerability-intelligence-mcp |
| Threat Actor | gti, feedly | otx-mcp, mcp-security-orkl | mallory-mcp-server |

### Routing Protocol
```
FOR EACH ioc IN enrichment_queue:
  DETERMINE ioc_type
  LOAD routing from adjusted_routing (from check-server-health)

  FOR EACH server IN primary_chain:
    CALL server.enrich(ioc)
    IF success: RECORD result, CONTINUE to secondary for additional context
    IF error: CLASSIFY error (lib/logging_schema.classify_error), APPLY recovery strategy, TRY next server

  FOR EACH server IN secondary_chain:
    CALL server.enrich(ioc)  # Additional context, not required
    IF success: MERGE with primary results
    IF error: LOG and CONTINUE (secondary failures are non-blocking)

  IF primary_chain returned no results:
    FOR EACH server IN fallback_chain:
      CALL server.enrich(ioc)
      IF success: USE as primary result with caveat
```

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

4. SECONDARY: CALL mcp-threatintel.lookup(hash)
   EXTRACT: abuse.ch MalwareBazaar data, ThreatFox associations

5. IF threat_label identified:
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

4. SECONDARY: CALL mcp-censys.search_certificates(domain)
   EXTRACT: TLS certificates, related domains, infrastructure

5. SECONDARY: CALL mcp-dnstwist.check(domain)
   EXTRACT: typosquatting variants, phishing indicators
```

### IP Address Enrichment
```
1. CALL gti.get_ip_address_report(ip)
   EXTRACT: reputation, asn, country, communicating_files

2. CALL mcp-shodan.search(ip)
   EXTRACT: open_ports, services, vulnerabilities, os_info

3. SECONDARY: CALL fastmcp-threatintel.analyze(ip)
   EXTRACT: vt_score, abuseipdb_score

4. SECONDARY: CALL mcp-threatintel.lookup(ip)
   EXTRACT: GreyNoise classification, abuse.ch Feodo tracker

5. FALLBACK: CALL networksdb-mcp.lookup(ip)
   EXTRACT: ASN, netblock, organization
```

### CVE Enrichment
```
1. CALL mcp-nvd.get_cve(cve_id)
   EXTRACT: description, cvss_score, cwe, affected_products

2. CALL epss-mcp.get_score(cve_id)
   EXTRACT: exploit_probability, percentile

3. CALL kev-mcp.check(cve_id)
   EXTRACT: in_kev_catalog, date_added, due_date

4. FALLBACK: CALL vulnerability-intelligence-mcp.analyze(cve_id)
   EXTRACT: unified CVE + EPSS + CVSS + exploit detection
```

### Threat Actor Enrichment
```
1. CALL gti.search_threat_actors(actor_name)
   EXTRACT: aliases, attribution_country, ttps, infrastructure

2. CALL feedly.get_actor_profile(actor_name)
   EXTRACT: recent_activity, campaigns, targeted_sectors

3. SECONDARY: CALL otx-mcp.get_pulses(actor_name)
   EXTRACT: community IOCs, related pulses

4. SECONDARY: CALL mcp-security-orkl.search(actor_name)
   EXTRACT: ORKL threat reports, historical analysis

5. FALLBACK: CALL mallory-mcp-server.search(actor_name)
   EXTRACT: real-time threat actor data
```

## Confidence Calculation

```python
confidence = (
  0.25 * gti_detection_ratio +      # VT detections / total engines
  0.25 * source_corroboration +     # Multiple sources agree (0-1)
  0.20 * behavioral_indicators +    # Sandbox results present (0-1)
  0.15 * temporal_relevance +       # Recency factor (0-1)
  0.15 * attribution_strength       # APT link confidence (0-1)
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
    "type": "hash|domain|ip|url|cve|threat_actor",
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
    "shodan": {
      "open_ports": [22, 80, 443],
      "services": ["ssh", "http", "https"]
    },
    "mcp-threatintel": {
      "greynoise": "malicious",
      "abuse_ch": {"feodo": false, "urlhaus": true}
    },
    "nvd": {
      "cvss_score": 9.8,
      "epss_score": 0.87,
      "in_kev": true
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
  "servers_queried": ["gti", "mcp-shodan", "mcp-threatintel"],
  "servers_failed": [],
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
| Shodan | 100/month | Prioritize P1/P2 IOCs only |
| Censys | 250/month | Use for domain enrichment only |
| AbuseIPDB | 1000/day | Prioritize high-confidence IOCs |
| NVD | 50/30s rolling | Batch CVE queries with delay |

## Cross-Validation Rules

- IOC flagged malicious by 3+ sources: **High confidence**
- IOC flagged malicious by 2 sources: **Medium-High confidence**
- IOC flagged by 1 source only: **Medium confidence**, note in gaps
- Contradictory results: **Low confidence**, flag for manual review
- CVE in KEV + EPSS > 0.5: **Critical priority**, escalate immediately

---
name: verify-claims
description: Independent fact-checking sub-agent that validates all extracted intelligence claims against authoritative source APIs before downstream propagation. Use after IOC enrichment and before report generation to ensure claim accuracy and prevent hallucination.
---

# Verification Agent Skill

## Purpose
Independently verify ALL factual claims, IOCs, and attribution statements extracted by upstream skills before they propagate to reports. Reduces hallucination risk and ensures intelligence product accuracy.

## Position in Workflow

```
monitor-feeds → enrich-iocs → **verify-claims** → diamond-model-analysis → generate-report
                                    ↓
                              Quarantine REFUTED
                              Flag UNVERIFIED
```

## Verification Workflow

### Step 1: Identify Source Type
For EACH claim from upstream:
- Determine originating platform (VirusTotal, MISP, OTX, Shodan, AbuseIPDB, etc.)
- Extract unique object identifier (hash, IP, domain, technique ID, CVE)
- Classify claim type: IOC, TTP, ATTRIBUTION, TEMPORAL, STATISTICAL

### Step 2: Construct Verification API Call

| Source | Identifier Type | Verification Endpoint | Key Attributes |
|--------|-----------------|----------------------|----------------|
| VirusTotal | SHA256/MD5 | `GET /api/v3/files/{hash}` | detection_stats, first_seen, names |
| VirusTotal | IP | `GET /api/v3/ip_addresses/{ip}` | as_owner, country, analysis_stats |
| VirusTotal | Domain | `GET /api/v3/domains/{domain}` | registrar, creation_date, analysis |
| Shodan | IP | `GET /shodan/host/{ip}` | ports, org, os, vulns |
| AbuseIPDB | IP | `GET /api/v2/check?ipAddress={ip}` | abuse_score, total_reports, country |
| AlienVault OTX | Pulse ID | `GET /api/v1/pulses/{id}` | name, created, indicators |
| URLhaus | URL/Hash | `POST /api/v1/url/` or `/payload/` | threat, url_status, tags |
| MISP | Event UUID | `GET /events/view/{uuid}` | info, date, threat_level, attributes |

### Step 3: Compare Attributes

| Match Type | Definition | Action |
|------------|------------|--------|
| EXACT | Value matches verbatim | Increment confidence |
| PARTIAL | Core attribute correct, metadata differs (e.g., timestamp ±24h) | Flag delta, accept |
| MISMATCH | Conflicting data on key attribute | Quarantine claim |
| NOT_FOUND | Object doesn't exist at source | Mark REFUTED if existence asserted |
| API_ERROR | Source unreachable or rate-limited | Retry 1x, then UNVERIFIED |

### Step 4: Assign Verification Status

```
VERIFIED_HIGH   = Exact match on ≥3 key attributes from primary source
VERIFIED_MEDIUM = Exact match on 1-2 key attributes OR partial match on ≥3
VERIFIED_LOW    = Single attribute match OR secondary source only
UNVERIFIED      = API error, source unavailable, or no verification attempted
REFUTED         = Mismatch on ≥1 key attribute OR object not found when existence claimed
```

### Step 5: Output Structured Result

```json
{
  "claim_id": "uuid",
  "original_claim": "SHA256 abc123 has 45 detections",
  "claim_type": "IOC",
  "source_platform": "virustotal",
  "object_identifier": "abc123...",
  "verification_status": "VERIFIED_HIGH",
  "confidence_score": 0.95,
  "attribute_checks": [
    {
      "attribute_name": "detection_count",
      "extracted_value": 45,
      "actual_value": 45,
      "match_type": "EXACT"
    }
  ],
  "api_response_timestamp": "2025-01-13T12:00:00Z",
  "api_http_status": 200,
  "discrepancies": [],
  "quarantine": false
}
```

## Failure Handling Protocol

| Failure Mode | Detection | Response |
|--------------|-----------|----------|
| Rate Limit (429) | HTTP 429 or Retry-After header | Exponential backoff: 2s → 4s → 8s; max 3 retries |
| Timeout | No response in 10s | Retry 1x, then UNVERIFIED |
| 404 Not Found | HTTP 404 | REFUTED if existence asserted |
| Auth Failure (401/403) | HTTP 401/403 | Log credential issue, UNVERIFIED, alert operator |
| Server Error (5xx) | HTTP 500-599 | Retry 1x after 5s, then UNVERIFIED |
| Malformed Response | JSON parse error | Log raw response, UNVERIFIED |
| Conflicting Sources | Source_A confirms, Source_B refutes | Output BOTH, flag for human adjudication |

## Confidence Weighting for Parent Agent

| Verification Status | Multiplier | Downstream Handling |
|--------------------|------------|---------------------|
| VERIFIED_HIGH | 1.0x | Include in final assessment |
| VERIFIED_MEDIUM | 0.75x | Include with caveat |
| VERIFIED_LOW | 0.5x | Include with strong caveat |
| UNVERIFIED | 0.25x | Prefix with `[UNVERIFIED]` |
| REFUTED | 0.0x | **Suppress entirely** unless human override |

## Constraints (IMMUTABLE)

1. **Never propagate REFUTED claims** without explicit human override
2. **UNVERIFIED claims** must carry `[UNVERIFIED]` prefix in all outputs
3. **Verification latency budget**: <5 seconds per claim; parallelize batch
4. **API key security**: Load from environment only; never log keys
5. **Idempotency**: Same claim + source = same result (cache 1 hour)
6. **Audit trail**: Log all API calls with timestamps

## Integration Points

- **Input**: Enriched IOCs from `enrich-iocs`, claims from `monitor-feeds`
- **Output**: Verified claims for `diamond-model-analysis` and `generate-report`
- **State**: Writes to `state/verification_cache.json`
- **Logs**: Writes to `logs/{date}.jsonl` with verification details

## MCP Tool Mapping

```
Claim about hash    → gti.get_file_report()      → Compare attributes
Claim about IP      → gti.get_ip_address_report() + fastmcp.analyze()
Claim about domain  → gti.get_domain_report()    → Compare attributes
Claim about actor   → gti.search_threat_actors() → Compare attributes
```

## Example Verification Flow

```
INPUT:
  Claim: "Hash abc123 has 45/70 detections, first seen 2024-01-15"
  
PROCESS:
  1. CALL gti.get_file_report(hash="abc123")
  2. EXTRACT: last_analysis_stats.malicious = 45 ✓
  3. EXTRACT: first_submission_date = 1705276800 → "2024-01-15" ✓
  4. MATCH COUNT: 2 exact matches
  
OUTPUT:
  verification_status: VERIFIED_MEDIUM (2 exact matches)
  confidence_score: 0.85
  quarantine: false
```

## Handoff to Report Generation

Verification results feed into `generate-report` skill:

```markdown
## IOC Table with Verification Status

| IOC | Type | Verification | Confidence |
|-----|------|--------------|------------|
| abc123... | SHA256 | ✓ VERIFIED_HIGH | 0.95 |
| evil[.]com | Domain | ⚠ UNVERIFIED | 0.25 |
| 1.2.3.4 | IP | ✗ REFUTED | 0.00 |
```

REFUTED IOCs are excluded from final report unless human override is set.

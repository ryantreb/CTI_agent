---
name: check-server-health
description: Run at session start to verify MCP server availability, check API keys, and report degraded capabilities. Adjusts the session execution plan based on available resources.
---

# Check Server Health Skill

## Purpose
Verify which MCP servers are available before beginning intelligence operations. Report degraded capabilities so downstream skills can adjust their routing.

## Position in Workflow

```
SESSION START → **check-server-health** → plan-session → monitor-feeds → ...
```

This skill runs FIRST in every session, before plan-session.

## Protocol

### Step 1: Load Server Registry
```
LOAD config/mcp_server_registry.json
EXTRACT all server entries with their tier, category, and API key requirements
```

### Step 2: Check API Key Availability
```
FOR EACH server WHERE requires_api_key == true:
  CHECK if api_key_env_var is set in environment
  IF missing:
    LOG warning: "{server_name} unavailable - missing {api_key_env_var}"
    ADD to unavailable_servers list
  ELSE:
    ADD to available_servers list

FOR EACH server WHERE requires_api_key == false:
  ADD to available_servers list (assumed available)
```

### Step 3: Generate Health Report
```
REPORT:
  - Total servers: {count}
  - Available: {count} ({percentage}%)
  - Unavailable: {count}
  - Missing API keys: [list]
  - Degraded capabilities: [human-readable list]
```

### Step 4: Adjust Routing Table
```
FOR EACH ioc_type IN routing table:
  REMOVE unavailable servers from primary/secondary/fallback chains
  IF primary chain is empty:
    PROMOTE secondary to primary
  IF all chains empty:
    LOG error: "No servers available for {ioc_type} enrichment"
    ADD to degraded_capabilities
```

### Step 5: Update Session State
```
WRITE health report to memory/scratchpad.md
UPDATE state/active_context.md with server availability
```

## Output Schema

```json
{
  "skill": "check-server-health",
  "timestamp": "ISO8601",
  "health": {
    "total_servers": 17,
    "available_count": 14,
    "unavailable_count": 3,
    "health_percentage": 82.4,
    "available_servers": ["gti", "otx-mcp", "mcp-threatintel", "..."],
    "unavailable_servers": ["mcp-shodan", "..."],
    "missing_keys": ["SHODAN_API_KEY"],
    "degraded_capabilities": [
      "IP enrichment via Shodan unavailable"
    ]
  },
  "adjusted_routing": {
    "ip": {"primary": ["gti"], "secondary": ["fastmcp-threatintel", "mcp-threatintel"], "fallback": []},
    "domain": {"primary": ["gti"], "secondary": ["mcp-dnstwist"], "fallback": []}
  }
}
```

## Severity Thresholds

| Health % | Severity | Action |
|----------|----------|--------|
| 90-100% | Green | Proceed normally |
| 70-89% | Yellow | Proceed with noted degradation |
| 50-69% | Orange | Warn user, limited enrichment |
| <50% | Red | Alert user, recommend fixing keys before proceeding |

## Integration

- **Runs before**: plan-session (always)
- **Output consumed by**: plan-session, enrich-iocs, verify-claims
- **State written to**: memory/scratchpad.md, state/active_context.md

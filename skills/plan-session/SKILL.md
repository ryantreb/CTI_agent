---
name: plan-session
description: Generate a prioritized execution plan at session start. Considers user goals, server availability (from check-server-health), stale items, and pending work. Must run before any collection or analysis skills.
---

# Plan Session Skill

## Purpose
Generate a prioritized execution plan based on user goals, available resources, and pending work from previous sessions.

## Position in Workflow

```
check-server-health → **plan-session** → [execute planned skills in order]
```

## Protocol

### Step 1: Gather Context
```
1. READ state/active_context.md for pending work from last session
2. READ memory/scratchpad.md for in-progress analysis
3. READ health report from check-server-health output
4. READ alerts/pending.json for unprocessed alerts
5. READ state/processed_guids.json for dedup context
6. PARSE user's stated goal/priority for this session
```

### Step 2: Determine Session Type
```
IF user specifies a target (APT, CVE, campaign):
  session_type = "focused"
  primary_goal = user_specified_target

ELIF pending alerts exist:
  session_type = "alert_response"
  primary_goal = highest_priority_alert

ELIF stale items need re-enrichment:
  session_type = "maintenance"
  primary_goal = "Re-enrich stale IOCs and update profiles"

ELSE:
  session_type = "discovery"
  primary_goal = "Scan feeds for new threats"
```

### Step 3: Build Execution Plan
```
ALWAYS include:
  1. check-server-health (already completed)

IF session_type == "focused":
  2. monitor-feeds (filtered to target topic)
  3. enrich-iocs (all IOCs from target)
  4. verify-claims
  5. diamond-model-analysis
  6. analysis-competing-hypotheses (if attribution needed)
  7. generate-report

IF session_type == "discovery":
  2. monitor-feeds (broad scan)
  3. enrich-iocs (top N by priority)
  4. verify-claims
  5. diamond-model-analysis (if sufficient data)
  6. generate-report (if analysis completed)

IF session_type == "alert_response":
  2. enrich-iocs (alert IOCs only, expedited)
  3. verify-claims
  4. diamond-model-analysis
  5. generate-report (tactical format)

IF session_type == "maintenance":
  2. [re-enrichment of stale items]
  3. [actor profile updates]
```

### Step 4: Adjust for Degraded Servers
```
FOR EACH planned skill:
  CHECK if required MCP servers are available
  IF not:
    ADD caveat to plan: "Limited enrichment - {server} unavailable"
    ADJUST expected outputs accordingly
```

### Step 5: Present Plan to User
```
OUTPUT:
  Session Type: {type}
  Primary Goal: {goal}
  Available Servers: {count}/{total} ({percentage}%)

  Execution Plan:
  1. [Skill] - [Purpose] - [Expected output]
  2. [Skill] - [Purpose] - [Expected output]
  ...

  Caveats:
  - [Any degraded capabilities]

  Estimated IOCs to process: {count}

  Proceed? (User confirms or adjusts)
```

## Output Schema

```json
{
  "skill": "plan-session",
  "timestamp": "ISO8601",
  "session_type": "focused|discovery|alert_response|maintenance",
  "primary_goal": "description",
  "execution_plan": [
    {
      "order": 1,
      "skill": "monitor-feeds",
      "purpose": "Collect intelligence on APT29 activity",
      "mcp_servers_required": ["feedly", "gti"],
      "expected_output": "Enrichment queue with relevant IOCs"
    }
  ],
  "caveats": ["Shodan unavailable - IP enrichment limited to GTI"],
  "estimated_items": 15,
  "user_confirmed": false
}
```

## Integration

- **Requires input from**: check-server-health
- **Output consumed by**: All downstream skills (determines execution order)
- **State written to**: state/active_context.md, memory/scratchpad.md

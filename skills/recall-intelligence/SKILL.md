---
name: recall-intelligence
description: Query Pinecone vector memory to surface relevant historical intelligence before new analysis. Use at the start of diamond-model-analysis and during plan-session to pre-load context from past sessions.
---

# Recall Intelligence Skill

## Purpose

Provide cross-session memory by searching historical intelligence stored in Pinecone. Surfaces relevant past reports, actor profiles, and IOC correlations to inform current analysis.

## Prerequisites

- Pinecone index `jtia-intel-memory` exists and is populated
- Pinecone MCP server is available (check via `check-server-health`)

## Use Cases

1. **Pre-analysis context**: Before `diamond-model-analysis`, recall related campaigns
2. **Actor history**: During adversary vertex population, pull historical actor profile
3. **IOC correlation**: Check if current IOCs appeared in past reports
4. **Session planning**: During `plan-session`, surface stale items needing re-evaluation

## Execution Protocol

```
THOUGHT: I'm starting a new analysis. Check Pinecone for relevant historical intelligence.

ACTION: Extract key entities from current analysis context:
  - Threat actor names and aliases
  - MITRE ATT&CK technique IDs
  - IOC values (IPs, domains, hashes)
  - Campaign names

ACTION: Build search queries using lib/pinecone_memory.build_search_query()
  Query 1: Actor-based — "What do we know about [actor]?"
  Query 2: TTP-based — "Campaigns using [technique IDs]"
  Query 3: IOC-based — "Reports containing [IOC values]"

ACTION: Execute searches via Pinecone MCP server (search-records tool)
OBSERVATION: Retrieved N relevant historical records

ACTION: Format results using lib/pinecone_memory.format_search_results()

ACTION: Summarize relevant context for downstream skills:
  - Related past reports (with dates and confidence)
  - Known actor profile updates
  - IOC overlap with historical campaigns
  - Confidence decay status of related items

CONCLUSION: Historical context loaded. {N} relevant records found.
  Forward context to diamond-model-analysis or plan-session.
```

## Integration Points

- **Called by**: `diamond-model-analysis` (before analysis), `plan-session` (priority planning)
- **Uses**: Pinecone MCP server (`search-records` tool)
- **Reads**: `actors/` profiles, `state/confidence_tracker.json`
- **Outputs**: Context summary passed to downstream skills

## Graceful Degradation

If Pinecone MCP server is unavailable:
1. Log degraded capability
2. Fall back to local `actors/` directory search via `lib/actor_profiles.find_actor_by_alias()`
3. Skip semantic search — analysis proceeds without historical context
4. Note in report: "Historical context unavailable (Pinecone offline)"

## Output

No file output — context is passed directly to downstream skills via the execution pipeline.
Record the recall operation in `logs/{date}.jsonl` with event_type `analysis`.

# JTIA Development Instructions

## What This Project Is

JTIA (Junior Threat Intel Agent) is an autonomous threat intelligence agent powered by Claude. It uses SKILL.md files as prompt instructions, MCP servers as data sources, and a self-evolving evaluation loop for quality improvement.

**Key distinction**: AGENT.md is the runtime brain (instructions Claude follows when *running* the agent). CLAUDE.md (this file) tells Claude Code how to *develop* the project.

## Architecture

- **SKILL.md files**: Prompt instructions for each capability (not Python code)
- **MCP servers**: External tools Claude calls for live data (configured in config/mcp_server_registry.json)
- **lib/**: Python utilities for config loading, logging, health checks
- **evaluation/**: Python graders for output quality assessment
- **state/**: JSON files for session persistence
- **config/**: Server registry, feeds, environment templates

## Development Conventions

### Adding a New MCP Server
1. Add entry to `config/mcp_server_registry.json`
2. Add routing entries if the server handles IOC types
3. Run `python scripts/generate_mcp_config.py` to regenerate mcp_config.json
4. Add tests in `tests/test_config.py`
5. Update `config/.env.template` if API key required

### Adding a New Skill
1. Create `skills/{skill-name}/SKILL.md` following the existing SKILL.md format
2. Add to AGENT.md skill registry with correct priority and dependencies
3. Add entry to `state/skill_versions.json`
4. Update AGENT.md execution loop if the skill changes workflow order

### Testing
- Run: `uv run --with pytest python -m pytest tests/ -v`
- JSON validation: All config/state files must be valid JSON
- Evaluation graders: `python evaluation/run_evaluation.py <source> <output>`

### Git Workflow
- `main`: Stable releases (tagged vX.Y.Z)
- `develop`: Integration branch
- `phase-N/*`: Feature branches per implementation phase
- Commit messages: `feat:`, `fix:`, `ci:`, `docs:` prefixes

## Current Phase: Phase 1 (MCP Server Expansion)

See `docs/plans/2026-02-16-jtia-v2-design.md` for full design.
See `docs/plans/2026-02-16-jtia-v2-phase1-plan.md` for implementation plan.

# CTI Agent Development Guide

**Version**: 2.4.0 | **Last Updated**: 2026-02-16

## Prerequisites

- Python 3.12+ (tested on 3.10, 3.11, 3.12)
- [uv](https://docs.astral.sh/uv/) package manager (mandatory — never use `pip` directly)
- Git
- Claude Code (for running CTI Agent as an agent)

## Setup

### 1. Clone and Configure

```bash
git clone <repo-url>
cd CTI_agent

# Configure API keys
cp config/.env.template config/.env
# Edit config/.env with your API keys
```

### 2. Install Dependencies

```bash
uv pip install -r requirements.txt
```

### 3. Install MCP Servers (Optional for Development)

Only needed if testing live MCP integration:

```bash
uvx gti_mcp       # Google Threat Intelligence / VirusTotal
```

### 4. Verify Setup

```bash
uv run --with pytest python -m pytest -q
# Expected: 182 passed
```

## Project Layout

```
CTI_agent/
├── AGENT.md                         # Master orchestrator prompt
├── agents/                          # Multi-agent team definitions
│   ├── README.md                    # Team overview
│   └── definitions/                 # Individual agent prompts
│       ├── collector.md
│       ├── analyst.md
│       ├── devils_advocate.md
│       ├── verifier.md
│       └── reporter.md
├── skills/                          # Skill prompt files
│   ├── orchestrate-team/SKILL.md    # Team pipeline orchestration
│   ├── monitor-feeds/SKILL.md       # Intelligence collection
│   ├── enrich-iocs/SKILL.md         # IOC enrichment
│   ├── verify-claims/SKILL.md       # Claim validation
│   ├── diamond-model-analysis/      # Intrusion analysis
│   ├── analysis-competing-hypotheses/ # Attribution testing
│   ├── generate-report/             # Report production (has references/)
│   ├── produce-stix-bundle/         # STIX 2.1 output
│   ├── produce-attack-layers/       # ATT&CK Navigator output
│   ├── recall-intelligence/         # Pinecone memory queries
│   ├── check-server-health/         # MCP availability checks
│   ├── plan-session/                # Session planning
│   ├── self-evolving-loop/          # Self-improvement
│   └── external/                    # Third-party skills (git submodules)
├── lib/                             # Python deterministic logic
│   ├── config.py                    # Registry loader
│   ├── health_check.py              # Health check utilities
│   ├── logging_schema.py            # Structured logging
│   ├── metrics.py                   # Observability
│   ├── confidence_decay.py          # IOC freshness decay
│   ├── actor_profiles.py            # Threat actor CRUD
│   ├── pinecone_memory.py           # Vector memory
│   ├── stix_builder.py              # Diamond → STIX converter
│   ├── attack_layers.py             # Diamond → ATT&CK layer
│   ├── team_data.py                 # Inter-agent data schemas
│   ├── debate.py                    # Debate engine
│   └── verification_pipeline.py     # Verification pipeline
├── evaluation/                      # Quality graders
│   ├── graders/                     # Python grading scripts
│   └── run_evaluation.py            # Evaluation orchestrator
├── config/                          # Configuration
│   ├── mcp_server_registry.json     # MCP server definitions (source of truth)
│   ├── mcp_config.json              # Claude Code MCP config (generated)
│   ├── team_config.json             # Multi-agent team config
│   ├── feeds.json                   # RSS fallback feeds
│   ├── skill_ownership.json         # Skill conflict resolution
│   └── .env.template                # API key template
├── tests/                           # Test suite
│   ├── test_integration.py          # Cross-cutting integration tests
│   ├── test_team_data.py            # Team data schema tests
│   ├── test_debate.py               # Debate engine tests
│   ├── test_verification_pipeline.py # Verification pipeline tests
│   └── ...                          # Per-module unit tests
├── state/                           # Runtime state (gitignored except schema)
├── demo/                            # Demo dataset and mock responses
├── docs/plans/                      # Design docs and implementation plans
├── templates/                       # Report templates
├── reports/                         # Generated output (gitignored)
├── logs/                            # Event logs (gitignored)
└── alerts/                          # Alert queue
```

## Development Workflow

### Running Tests

```bash
# All tests (quiet mode preferred)
uv run --with pytest python -m pytest -q

# Specific test file
uv run --with pytest python -m pytest tests/test_debate.py -q

# Single test
uv run --with pytest python -m pytest tests/test_debate.py::TestShouldChallenge::test_highly_likely_must_challenge -q
```

### Linting and Formatting

```bash
# Format
ruff format .

# Lint (with auto-fix)
ruff check . --fix
```

### Adding a New Python Module

1. Create `lib/your_module.py`
2. Create `tests/test_your_module.py` with failing tests first (TDD)
3. Implement until tests pass
4. Run `ruff format . && ruff check . --fix`
5. Add integration tests to `tests/test_integration.py` if cross-cutting

### Adding a New Skill

1. Create `skills/your-skill/SKILL.md` with YAML frontmatter
2. Add reference materials to `skills/your-skill/references/` if needed
3. Add to AGENT.md skill registry table
4. Add to `state/skill_versions.json`
5. Add existence check to `tests/test_integration.py`

### Adding a New Agent Definition

1. Create `agents/definitions/your_agent.md` with YAML frontmatter
2. Update `agents/README.md`
3. Add to `config/team_config.json`
4. Add to `skills/orchestrate-team/SKILL.md` pipeline
5. Add to `AGENT.md` Multi-Agent Team section

### Updating MCP Server Registry

The registry (`config/mcp_server_registry.json`) is the single source of truth:

1. Edit the registry file
2. Regenerate Claude Code config: `uv run python scripts/generate_mcp_config.py`
3. Verify sync: CI runs `mcp-config-sync` check automatically

## Code Standards

### Python Style

- **Type hints**: Required on public functions. Modern syntax: `list[int]`, `Item | None`
- **Docstrings**: One-line for most functions. Multi-line only for complex logic
- **Imports**: Standard → Third-party → Local (ruff auto-sorts)
- **No bare `except`**: Catch specific exceptions
- **Pathlib**: Use `Path` over `os.path`

### File Size Limits

- Production files: 300 lines soft limit, 500 lines hard limit
- Test files: No strict limit, but prefer focused test classes

### Commit Messages

Format: `feat|fix|docs|test|refactor(scope): description`

Examples:
- `feat(agents): add Verifier agent definition`
- `fix(debate): correct consensus threshold calculation`
- `test: add Phase 4 integration tests`

## CI/CD

GitHub Actions (`.github/workflows/test.yml`) runs three jobs:

| Job | Purpose |
|-----|---------|
| `test` | Run pytest across Python 3.10/3.11/3.12 |
| `validate-json` | Validate all `config/*.json` files |
| `mcp-config-sync` | Ensure `mcp_config.json` matches the registry |

## Key Patterns

### Factory Functions for Data Schemas

All inter-agent data uses factory functions in `lib/team_data.py`:

```python
from lib.team_data import create_key_judgment

judgment = create_key_judgment(
    judgment_id="KJ1",
    statement="APT29 is likely responsible",
    confidence="likely",
    confidence_numeric=0.70,
    supporting_evidence=["E1", "E2"],
)
# Returns: {"type": "key_judgment", "judgment_id": "KJ1", ...}
```

### Debate Engine Logic

`lib/debate.py` provides deterministic challenge logic:
- `should_challenge(judgment)` — mandatory for "highly likely" / "almost certain"
- `generate_challenge_types(judgment)` — returns challenge strategies based on content
- `check_consensus(challenges, responses, round)` — determines if debate should continue
- `build_alternative_analysis_section(record)` — generates ICD 203 Alternative Analysis markdown

### Verification Pipeline

`lib/verification_pipeline.py` routes claims to appropriate MCP servers:
- IOC claims → `mcp_verification` (GTI, Shodan, Censys)
- TTP claims → `attack_lookup` (ATT&CK validation)
- Attribution claims → `multi_source_verification` (multiple intel sources)

### Confidence Decay

IOC confidence decays over time with configurable half-lives:
- IP addresses: 30 days
- Domains: 90 days
- File hashes: 365 days
- URLs: 14 days

## Troubleshooting

### Tests Fail with `ModuleNotFoundError`

Ensure you're running with uv: `uv run --with pytest python -m pytest -q`

### `mcp_config.json` Out of Sync

Regenerate: `uv run python scripts/generate_mcp_config.py`

### Version Test Fails After Bump

Update the version assertion in `tests/test_integration.py::TestVersionTracking`.

# External Skills

Third-party skills integrated into CTI Agent. Each subdirectory contains skills
from an external source, installed per the project's skill conflict resolution
policy (see AGENT.md).

## Sources

| Directory | Source | Skills |
|-----------|--------|--------|
| `malware-analysis/` | [gl0bal01/malware-analysis-claude-skills](https://github.com/gl0bal01/malware-analysis-claude-skills) | 5 |
| `yara-rule-skill/` | [YARAHQ/yara-rule-skill](https://github.com/YARAHQ/yara-rule-skill) | 1 |
| `trailofbits/` | [trailofbits/skills](https://github.com/trailofbits/skills) | 6 |

## Conflict Resolution

- **YARA rules**: YARAHQ skill is primary author
- **Sigma rules**: gl0bal01's detection-engineer is primary author
- **Reports**: CTI Agent's generate-report orchestrates, delegates detection rules

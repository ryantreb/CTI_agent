# CTI Agent Demo Mode

Run the full CTI Agent pipeline with synthetic data and mock MCP responses.
No API keys required.

## Quick Start

```bash
chmod +x demo/run_demo.sh
./demo/run_demo.sh
```

## Contents

| File/Directory | Purpose |
|---------------|---------|
| `sample_input.json` | Synthetic APT29 threat report with IOCs and TTPs |
| `mock_mcp_responses/` | Cached MCP server responses for demo IOCs |
| `expected_output/` | Reference outputs at each pipeline stage |
| `run_demo.sh` | End-to-end pipeline runner |
| `output/` | Generated outputs (created by run_demo.sh) |

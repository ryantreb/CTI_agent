#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== CTI Agent Demo Mode ==="
echo "Using mock MCP responses (no API keys required)"
echo ""

export CTI_AGENT_DEMO_MODE=true

# Step 1: Generate STIX bundle from demo Diamond Model
echo "[1/3] Generating STIX 2.1 bundle from demo Diamond Model..."
uv run python -c "
import json
from lib.stix_builder import diamond_to_stix
with open('$SCRIPT_DIR/expected_output/diamond_model.json') as f:
    diamond = json.load(f)
bundle = diamond_to_stix(diamond)
output_path = '$SCRIPT_DIR/output/demo_stix_bundle.json'
import os; os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, 'w') as f:
    json.dump(bundle, f, indent=2)
print(f'  -> STIX bundle: {output_path} ({len(bundle[\"objects\"])} objects)')
"

# Step 2: Generate ATT&CK Navigator layer
echo "[2/3] Generating ATT&CK Navigator layer..."
uv run python -c "
import json
from lib.attack_layers import diamond_to_layer
with open('$SCRIPT_DIR/expected_output/diamond_model.json') as f:
    diamond = json.load(f)
layer = diamond_to_layer(diamond, report_guid='demo-001')
output_path = '$SCRIPT_DIR/output/demo_attack_layer.json'
with open(output_path, 'w') as f:
    json.dump(layer, f, indent=2)
print(f'  -> ATT&CK layer: {output_path} ({len(layer[\"techniques\"])} techniques)')
"

# Step 3: Run health check
echo "[3/3] Running health check..."
uv run python -c "
from lib.health_check import run_health_check
report = run_health_check()
print(f'  -> Servers: {report[\"total_servers\"]} total, {report[\"available_count\"]} available')
print(f'  -> Health: {report[\"health_percentage\"]:.0f}%')
"

echo ""
echo "=== Demo Complete ==="
echo "Output files in: $SCRIPT_DIR/output/"

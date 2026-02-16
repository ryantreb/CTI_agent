#!/usr/bin/env python3
"""
Generate config/mcp_config.json from the MCP server registry.

Usage:
    uv run python scripts/generate_mcp_config.py
"""

import json
import sys
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.config import generate_mcp_config

OUTPUT_PATH = Path(__file__).parent.parent / "config" / "mcp_config.json"


def main() -> None:
    config = generate_mcp_config()
    OUTPUT_PATH.write_text(json.dumps(config, indent=2) + "\n")
    server_count = len(config["mcpServers"])
    print(f"Generated {OUTPUT_PATH} with {server_count} servers.")


if __name__ == "__main__":
    main()

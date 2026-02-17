"""Metrics collection for CTI Agent observability.

Appends structured metrics to state/metrics.jsonl for trend analysis.
Metrics include IOC enrichment counts, confidence scores, MCP response
times, and grader scores.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def create_metric(
    session_id: str,
    metric_type: str,
    value: int | float,
    *,
    metadata: dict | None = None,
) -> dict:
    """Create a structured metric entry."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "metric_type": metric_type,
        "value": value,
        "metadata": metadata or {},
    }


def append_metric(metric: dict, metrics_file: Path) -> None:
    """Append a metric to the JSONL file."""
    with open(metrics_file, "a") as f:
        f.write(json.dumps(metric) + "\n")


def load_metrics(metrics_file: Path) -> list[dict]:
    """Load all metrics from the JSONL file."""
    if not metrics_file.exists():
        return []
    metrics = []
    for line in metrics_file.read_text().strip().splitlines():
        if line:
            metrics.append(json.loads(line))
    return metrics


def summarize_session_metrics(session_id: str, metrics_file: Path) -> dict:
    """Summarize metrics for a specific session."""
    all_metrics = load_metrics(metrics_file)
    session_metrics = [m for m in all_metrics if m["session_id"] == session_id]
    return {
        "session_id": session_id,
        "metric_count": len(session_metrics),
        "metrics": session_metrics,
    }

"""Tests for metrics collection."""

from lib.metrics import (
    create_metric,
    append_metric,
    load_metrics,
    summarize_session_metrics,
)


class TestCreateMetric:
    def test_creates_ioc_metric(self):
        metric = create_metric(
            session_id="sess-001",
            metric_type="iocs_enriched",
            value=15,
        )
        assert metric["metric_type"] == "iocs_enriched"
        assert metric["value"] == 15
        assert "timestamp" in metric

    def test_creates_confidence_metric(self):
        metric = create_metric(
            session_id="sess-001",
            metric_type="avg_confidence",
            value=0.72,
            metadata={"skill": "enrich-iocs"},
        )
        assert metric["value"] == 0.72
        assert metric["metadata"]["skill"] == "enrich-iocs"

    def test_creates_response_time_metric(self):
        metric = create_metric(
            session_id="sess-001",
            metric_type="mcp_response_time_ms",
            value=250,
            metadata={"server": "gti"},
        )
        assert metric["value"] == 250


class TestAppendAndLoad:
    def test_append_and_load_roundtrip(self, tmp_path):
        metrics_file = tmp_path / "metrics.jsonl"
        m1 = create_metric("sess-001", "iocs_enriched", 10)
        m2 = create_metric("sess-001", "avg_confidence", 0.8)

        append_metric(m1, metrics_file)
        append_metric(m2, metrics_file)

        loaded = load_metrics(metrics_file)
        assert len(loaded) == 2
        assert loaded[0]["metric_type"] == "iocs_enriched"

    def test_load_empty_file(self, tmp_path):
        metrics_file = tmp_path / "metrics.jsonl"
        assert load_metrics(metrics_file) == []


class TestSummarizeSessionMetrics:
    def test_summarizes_session(self, tmp_path):
        metrics_file = tmp_path / "metrics.jsonl"
        for i in range(5):
            append_metric(
                create_metric("sess-001", "iocs_enriched", 3 + i), metrics_file
            )
        append_metric(create_metric("sess-002", "iocs_enriched", 99), metrics_file)

        summary = summarize_session_metrics("sess-001", metrics_file)
        assert summary["session_id"] == "sess-001"
        assert summary["metric_count"] == 5

    def test_empty_session(self, tmp_path):
        metrics_file = tmp_path / "metrics.jsonl"
        summary = summarize_session_metrics("nonexistent", metrics_file)
        assert summary["metric_count"] == 0

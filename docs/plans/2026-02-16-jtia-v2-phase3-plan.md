# CTI Agent v2.3.0 Phase 3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add persistent intelligence memory via Pinecone vector search, threat actor profiles that accumulate across sessions, confidence decay with automatic re-evaluation triggers, and metrics collection.

**Architecture:** Phase 3 adds a semantic memory layer (Pinecone) so CTI Agent can recall relevant historical intelligence during analysis. Threat actor profiles persist in `actors/` as JSON files and are also upserted to Pinecone for cross-session search. A confidence decay engine tracks IOC/assessment freshness using configurable half-lives, triggering re-enrichment when confidence drops below threshold. Metrics collection extends the existing logging schema.

**Tech Stack:** Python 3.12+, pytest, Pinecone MCP server (existing), CTI Agent SKILL.md prompt orchestration, JSON state files

---

### Task 1: Confidence Decay Library — Tests

**Files:**
- Create: `tests/test_confidence_decay.py`

**Step 1: Write failing tests**

```python
"""Tests for confidence decay calculations."""
import json
from datetime import datetime, timezone, timedelta

import pytest

from lib.confidence_decay import (
    calculate_decay,
    decay_status,
    HALF_LIVES,
    create_tracked_item,
    scan_for_stale_items,
    apply_decay_to_tracker,
)


class TestHalfLives:
    """Half-life constants are defined per IOC type."""

    def test_ip_half_life(self):
        assert HALF_LIVES["ip"] == 30

    def test_domain_half_life(self):
        assert HALF_LIVES["domain"] == 90

    def test_hash_half_life(self):
        assert HALF_LIVES["hash"] == 365

    def test_url_half_life(self):
        assert HALF_LIVES["url"] == 14

    def test_ttp_half_life(self):
        assert HALF_LIVES["ttp"] == 730

    def test_actor_half_life(self):
        assert HALF_LIVES["actor"] == 365


class TestCalculateDecay:
    """Decay formula: current = original * max(0.1, 1 - (days / half_life))."""

    def test_no_decay_at_zero_days(self):
        result = calculate_decay(original_confidence=0.85, days_elapsed=0, half_life_days=30)
        assert result == pytest.approx(0.85)

    def test_half_decay_at_half_life(self):
        result = calculate_decay(original_confidence=1.0, days_elapsed=30, half_life_days=30)
        assert result == pytest.approx(0.1)  # max(0.1, 1 - 30/30) = max(0.1, 0) = 0.1

    def test_partial_decay(self):
        result = calculate_decay(original_confidence=0.80, days_elapsed=15, half_life_days=30)
        # factor = max(0.1, 1 - 15/30) = max(0.1, 0.5) = 0.5
        assert result == pytest.approx(0.40)

    def test_floor_at_minimum(self):
        result = calculate_decay(original_confidence=0.90, days_elapsed=500, half_life_days=30)
        assert result == pytest.approx(0.09)  # 0.90 * 0.1 = 0.09

    def test_ip_decay_30_days(self):
        result = calculate_decay(original_confidence=0.85, days_elapsed=15, half_life_days=HALF_LIVES["ip"])
        assert result == pytest.approx(0.425)


class TestDecayStatus:
    """Status classification based on current confidence."""

    def test_active_above_0_5(self):
        assert decay_status(0.7) == "active"

    def test_stale_between_0_3_and_0_5(self):
        assert decay_status(0.4) == "stale"

    def test_expired_below_0_3(self):
        assert decay_status(0.2) == "expired"

    def test_boundary_0_5_is_active(self):
        assert decay_status(0.5) == "active"

    def test_boundary_0_3_is_stale(self):
        assert decay_status(0.3) == "stale"


class TestCreateTrackedItem:
    def test_creates_valid_item(self):
        item = create_tracked_item(
            item_id="ioc-abc",
            ioc_type="ip",
            value="1.2.3.4",
            original_confidence=0.85,
        )
        assert item["item_id"] == "ioc-abc"
        assert item["type"] == "ip"
        assert item["value"] == "1.2.3.4"
        assert item["original_confidence"] == 0.85
        assert item["half_life_days"] == 30
        assert "last_verified" in item

    def test_uses_correct_half_life_for_domain(self):
        item = create_tracked_item("ioc-xyz", "domain", "evil.com", 0.70)
        assert item["half_life_days"] == 90


class TestScanForStaleItems:
    def test_finds_stale_items(self):
        now = datetime.now(timezone.utc)
        tracker = {
            "tracked_items": [
                {
                    "item_id": "old-ip",
                    "type": "ip",
                    "value": "1.2.3.4",
                    "original_confidence": 0.85,
                    "last_verified": (now - timedelta(days=25)).isoformat(),
                    "half_life_days": 30,
                },
                {
                    "item_id": "fresh-hash",
                    "type": "hash",
                    "value": "abc123",
                    "original_confidence": 0.90,
                    "last_verified": (now - timedelta(days=5)).isoformat(),
                    "half_life_days": 365,
                },
            ]
        }
        stale = scan_for_stale_items(tracker)
        # The IP has decayed significantly (25/30 days elapsed)
        assert any(item["item_id"] == "old-ip" for item in stale)

    def test_empty_tracker_returns_empty(self):
        assert scan_for_stale_items({"tracked_items": []}) == []


class TestApplyDecayToTracker:
    def test_updates_current_confidence(self):
        now = datetime.now(timezone.utc)
        tracker = {
            "tracked_items": [
                {
                    "item_id": "test-ip",
                    "type": "ip",
                    "value": "1.2.3.4",
                    "original_confidence": 0.80,
                    "last_verified": (now - timedelta(days=15)).isoformat(),
                    "half_life_days": 30,
                    "current_confidence": 0.80,
                    "decay_status": "active",
                },
            ]
        }
        updated = apply_decay_to_tracker(tracker)
        item = updated["tracked_items"][0]
        assert item["current_confidence"] == pytest.approx(0.40)
        assert item["decay_status"] == "stale"
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_confidence_decay.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.confidence_decay'`

**Step 3: Commit**

```bash
git add tests/test_confidence_decay.py
git commit -m "test: add confidence decay tests (red phase)"
```

---

### Task 2: Confidence Decay Library — Implementation

**Files:**
- Create: `lib/confidence_decay.py`

**Step 1: Implement confidence decay**

```python
"""Confidence decay engine for IOC and assessment freshness tracking.

Uses configurable half-lives per IOC type. Decay formula:
  current = original * max(0.1, 1 - (days_elapsed / half_life_days))
"""
from datetime import datetime, timezone


HALF_LIVES: dict[str, int] = {
    "ip": 30,
    "domain": 90,
    "hash": 365,
    "url": 14,
    "ttp": 730,
    "actor": 365,
}


def calculate_decay(
    original_confidence: float,
    days_elapsed: int | float,
    half_life_days: int,
) -> float:
    """Apply linear decay with floor at 10% of original."""
    decay_factor = max(0.1, 1.0 - (days_elapsed / half_life_days))
    return original_confidence * decay_factor


def decay_status(current_confidence: float) -> str:
    """Classify decay status based on current confidence level."""
    if current_confidence >= 0.5:
        return "active"
    if current_confidence >= 0.3:
        return "stale"
    return "expired"


def create_tracked_item(
    item_id: str,
    ioc_type: str,
    value: str,
    original_confidence: float,
) -> dict:
    """Create a new tracked item for the confidence tracker."""
    half_life = HALF_LIVES.get(ioc_type, 365)
    now = datetime.now(timezone.utc).isoformat()
    return {
        "item_id": item_id,
        "type": ioc_type,
        "value": value,
        "original_confidence": original_confidence,
        "last_verified": now,
        "half_life_days": half_life,
        "current_confidence": original_confidence,
        "decay_status": "active",
    }


def _days_since(iso_timestamp: str) -> float:
    """Calculate days elapsed since an ISO timestamp."""
    then = datetime.fromisoformat(iso_timestamp)
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - then).total_seconds() / 86400


def scan_for_stale_items(tracker: dict, threshold: float = 0.3) -> list[dict]:
    """Return items whose decayed confidence falls below threshold."""
    stale = []
    for item in tracker.get("tracked_items", []):
        days = _days_since(item["last_verified"])
        current = calculate_decay(
            item["original_confidence"], days, item["half_life_days"]
        )
        if current < threshold:
            stale.append({**item, "current_confidence": current})
    return stale


def apply_decay_to_tracker(tracker: dict) -> dict:
    """Recalculate current_confidence and decay_status for all tracked items."""
    for item in tracker.get("tracked_items", []):
        days = _days_since(item["last_verified"])
        item["current_confidence"] = calculate_decay(
            item["original_confidence"], days, item["half_life_days"]
        )
        item["decay_status"] = decay_status(item["current_confidence"])
    return tracker
```

**Step 2: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_confidence_decay.py -q`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add lib/confidence_decay.py
git commit -m "feat: add confidence decay engine with half-life calculations"
```

---

### Task 3: Confidence Tracker State File

**Files:**
- Create: `state/confidence_tracker.json`

**Step 1: Create empty tracker**

```json
{
  "schema_version": "1.0",
  "last_scan": null,
  "tracked_items": []
}
```

**Step 2: Commit**

```bash
git add state/confidence_tracker.json
git commit -m "feat: add confidence tracker state file"
```

---

### Task 4: Threat Actor Profile Library — Tests

**Files:**
- Create: `tests/test_actor_profiles.py`

**Step 1: Write failing tests**

```python
"""Tests for threat actor profile management."""
import json
from pathlib import Path
from datetime import datetime, timezone

import pytest

from lib.actor_profiles import (
    create_actor_profile,
    load_actor_profile,
    save_actor_profile,
    update_actor_profile,
    find_actor_by_alias,
    list_actors,
)


@pytest.fixture
def actors_dir(tmp_path):
    """Create a temporary actors directory."""
    d = tmp_path / "actors"
    d.mkdir()
    return d


class TestCreateActorProfile:
    def test_creates_basic_profile(self):
        profile = create_actor_profile(
            actor_id="APT29",
            aliases=["Cozy Bear", "The Dukes"],
            motivation="espionage",
            nation_state="Russia",
        )
        assert profile["actor_id"] == "APT29"
        assert "Cozy Bear" in profile["aliases"]
        assert profile["motivation"] == "espionage"
        assert profile["known_ttps"] == []
        assert profile["known_infrastructure"] == []
        assert profile["reports"] == []
        assert "first_tracked" in profile

    def test_creates_minimal_profile(self):
        profile = create_actor_profile(actor_id="Unknown-001")
        assert profile["actor_id"] == "Unknown-001"
        assert profile["aliases"] == []
        assert profile["attribution_confidence"] == "unknown"


class TestSaveAndLoadProfile:
    def test_save_and_load_roundtrip(self, actors_dir):
        profile = create_actor_profile(
            actor_id="FIN7",
            aliases=["Carbanak"],
            motivation="financial",
        )
        save_actor_profile(profile, actors_dir)
        loaded = load_actor_profile("FIN7", actors_dir)
        assert loaded["actor_id"] == "FIN7"
        assert "Carbanak" in loaded["aliases"]

    def test_load_nonexistent_returns_none(self, actors_dir):
        assert load_actor_profile("DOESNOTEXIST", actors_dir) is None

    def test_filename_is_slugified(self, actors_dir):
        profile = create_actor_profile(actor_id="Lazarus Group")
        save_actor_profile(profile, actors_dir)
        assert (actors_dir / "lazarus-group.json").exists()


class TestUpdateActorProfile:
    def test_add_ttp(self, actors_dir):
        profile = create_actor_profile(actor_id="APT29")
        save_actor_profile(profile, actors_dir)

        updated = update_actor_profile(
            "APT29",
            actors_dir,
            add_ttps=[{"technique": "T1566.001", "confidence": "high", "first_observed": "2026-02-16"}],
        )
        assert len(updated["known_ttps"]) == 1
        assert updated["known_ttps"][0]["technique"] == "T1566.001"

    def test_add_infrastructure(self, actors_dir):
        profile = create_actor_profile(actor_id="APT29")
        save_actor_profile(profile, actors_dir)

        updated = update_actor_profile(
            "APT29",
            actors_dir,
            add_infrastructure=[{"type": "domain", "value": "evil.com", "status": "active"}],
        )
        assert len(updated["known_infrastructure"]) == 1

    def test_add_report_reference(self, actors_dir):
        profile = create_actor_profile(actor_id="APT29")
        save_actor_profile(profile, actors_dir)

        updated = update_actor_profile("APT29", actors_dir, add_reports=["report-abc"])
        assert "report-abc" in updated["reports"]

    def test_no_duplicate_reports(self, actors_dir):
        profile = create_actor_profile(actor_id="APT29")
        save_actor_profile(profile, actors_dir)

        update_actor_profile("APT29", actors_dir, add_reports=["report-abc"])
        updated = update_actor_profile("APT29", actors_dir, add_reports=["report-abc"])
        assert updated["reports"].count("report-abc") == 1


class TestFindActorByAlias:
    def test_finds_by_alias(self, actors_dir):
        profile = create_actor_profile(
            actor_id="APT29", aliases=["Cozy Bear", "The Dukes"]
        )
        save_actor_profile(profile, actors_dir)

        result = find_actor_by_alias("Cozy Bear", actors_dir)
        assert result is not None
        assert result["actor_id"] == "APT29"

    def test_finds_by_actor_id(self, actors_dir):
        profile = create_actor_profile(actor_id="APT29")
        save_actor_profile(profile, actors_dir)

        result = find_actor_by_alias("APT29", actors_dir)
        assert result is not None

    def test_returns_none_for_unknown(self, actors_dir):
        assert find_actor_by_alias("NOPE", actors_dir) is None


class TestListActors:
    def test_lists_all_actors(self, actors_dir):
        for name in ("APT29", "FIN7", "Lazarus Group"):
            save_actor_profile(create_actor_profile(actor_id=name), actors_dir)

        actors = list_actors(actors_dir)
        assert len(actors) == 3
        ids = {a["actor_id"] for a in actors}
        assert "APT29" in ids
        assert "FIN7" in ids

    def test_empty_directory(self, actors_dir):
        assert list_actors(actors_dir) == []
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_actor_profiles.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.actor_profiles'`

**Step 3: Commit**

```bash
git add tests/test_actor_profiles.py
git commit -m "test: add threat actor profile tests (red phase)"
```

---

### Task 5: Threat Actor Profile Library — Implementation

**Files:**
- Create: `lib/actor_profiles.py`

**Step 1: Implement actor profiles**

```python
"""Persistent threat actor profile management.

Profiles accumulate across sessions in actors/ directory as JSON files.
Actor IDs are slugified for filenames (e.g., "Lazarus Group" -> "lazarus-group.json").
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def _slugify(name: str) -> str:
    """Convert actor name to filesystem-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def create_actor_profile(
    actor_id: str,
    *,
    aliases: list[str] | None = None,
    attribution_confidence: str = "unknown",
    motivation: str = "",
    nation_state: str = "",
) -> dict:
    """Create a new actor profile."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return {
        "actor_id": actor_id,
        "aliases": aliases or [],
        "attribution_confidence": attribution_confidence,
        "motivation": motivation,
        "nation_state": nation_state,
        "first_tracked": now,
        "last_updated": now,
        "known_ttps": [],
        "known_infrastructure": [],
        "known_malware": [],
        "targeting": {"sectors": [], "geographies": []},
        "reports": [],
        "assessment_history": [],
    }


def _profile_path(actor_id: str, actors_dir: Path) -> Path:
    return actors_dir / f"{_slugify(actor_id)}.json"


def save_actor_profile(profile: dict, actors_dir: Path) -> Path:
    """Save an actor profile to disk."""
    profile["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = _profile_path(profile["actor_id"], actors_dir)
    path.write_text(json.dumps(profile, indent=2))
    return path


def load_actor_profile(actor_id: str, actors_dir: Path) -> dict | None:
    """Load an actor profile by ID. Returns None if not found."""
    path = _profile_path(actor_id, actors_dir)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def update_actor_profile(
    actor_id: str,
    actors_dir: Path,
    *,
    add_ttps: list[dict] | None = None,
    add_infrastructure: list[dict] | None = None,
    add_reports: list[str] | None = None,
    add_malware: list[str] | None = None,
) -> dict:
    """Update an existing actor profile with new intelligence."""
    profile = load_actor_profile(actor_id, actors_dir)
    if profile is None:
        raise ValueError(f"Actor profile '{actor_id}' not found")

    if add_ttps:
        existing_techniques = {t["technique"] for t in profile["known_ttps"]}
        for ttp in add_ttps:
            if ttp["technique"] not in existing_techniques:
                profile["known_ttps"].append(ttp)
                existing_techniques.add(ttp["technique"])

    if add_infrastructure:
        existing_infra = {
            (i["type"], i["value"]) for i in profile["known_infrastructure"]
        }
        for infra in add_infrastructure:
            key = (infra["type"], infra["value"])
            if key not in existing_infra:
                profile["known_infrastructure"].append(infra)
                existing_infra.add(key)

    if add_reports:
        existing_reports = set(profile["reports"])
        for report in add_reports:
            if report not in existing_reports:
                profile["reports"].append(report)
                existing_reports.add(report)

    if add_malware:
        existing_malware = set(profile["known_malware"])
        for mal in add_malware:
            if mal not in existing_malware:
                profile["known_malware"].append(mal)
                existing_malware.add(mal)

    save_actor_profile(profile, actors_dir)
    return profile


def find_actor_by_alias(name: str, actors_dir: Path) -> dict | None:
    """Search for an actor by alias or actor_id across all profiles."""
    for path in actors_dir.glob("*.json"):
        profile = json.loads(path.read_text())
        if profile["actor_id"] == name or name in profile.get("aliases", []):
            return profile
    return None


def list_actors(actors_dir: Path) -> list[dict]:
    """List all actor profiles (summary: actor_id, aliases, last_updated)."""
    actors = []
    for path in sorted(actors_dir.glob("*.json")):
        profile = json.loads(path.read_text())
        actors.append(profile)
    return actors
```

**Step 2: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_actor_profiles.py -q`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add lib/actor_profiles.py
git commit -m "feat: add threat actor profile management library"
```

---

### Task 6: Actors Directory Setup

**Files:**
- Create: `actors/.gitkeep`
- Create: `actors/README.md`

**Step 1: Create actors directory**

Create `actors/README.md`:

```markdown
# Threat Actor Profiles

Persistent JSON profiles that accumulate across sessions.

- One file per actor (slugified name: `apt29.json`, `lazarus-group.json`)
- Updated automatically by `diamond-model-analysis` skill
- Queried during analysis for historical context
- Upserted to Pinecone for semantic search via `recall-intelligence` skill

See `lib/actor_profiles.py` for the profile schema and management API.
```

**Step 2: Commit**

```bash
git add actors/
git commit -m "feat: add actors directory for persistent threat profiles"
```

---

### Task 7: Metrics Collection Library — Tests

**Files:**
- Create: `tests/test_metrics.py`

**Step 1: Write failing tests**

```python
"""Tests for metrics collection."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

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
        append_metric(
            create_metric("sess-002", "iocs_enriched", 99), metrics_file
        )

        summary = summarize_session_metrics("sess-001", metrics_file)
        assert summary["session_id"] == "sess-001"
        assert summary["metric_count"] == 5

    def test_empty_session(self, tmp_path):
        metrics_file = tmp_path / "metrics.jsonl"
        summary = summarize_session_metrics("nonexistent", metrics_file)
        assert summary["metric_count"] == 0
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_metrics.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.metrics'`

**Step 3: Commit**

```bash
git add tests/test_metrics.py
git commit -m "test: add metrics collection tests (red phase)"
```

---

### Task 8: Metrics Collection Library — Implementation

**Files:**
- Create: `lib/metrics.py`
- Create: `state/metrics.jsonl`

**Step 1: Implement metrics collection**

```python
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
```

**Step 2: Create empty metrics file**

Create `state/metrics.jsonl` as an empty file (touch it).

**Step 3: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_metrics.py -q`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add lib/metrics.py state/metrics.jsonl
git commit -m "feat: add metrics collection library and state file"
```

---

### Task 9: Pinecone Memory Library — Tests

**Files:**
- Create: `tests/test_pinecone_memory.py`

**Step 1: Write failing tests**

These tests are unit tests that mock the Pinecone MCP interaction. They test the record schema construction and query formatting, not actual Pinecone calls.

```python
"""Tests for Pinecone vector memory integration.

Tests record schema construction and query formatting.
Actual Pinecone calls are mocked — live integration tested via demo mode.
"""
import pytest

from lib.pinecone_memory import (
    PINECONE_INDEX,
    build_intel_record,
    build_actor_record,
    build_search_query,
    format_search_results,
)


class TestBuildIntelRecord:
    def test_creates_record_from_report(self):
        record = build_intel_record(
            report_guid="rpt-001",
            summary="APT29 targets government agencies via supply chain compromise",
            report_type="tactical",
            threat_actors=["APT29"],
            ttps=["T1195.002", "T1059.001"],
            ioc_types=["ip", "domain", "hash"],
            confidence=0.85,
            campaign="SolarWinds",
        )
        assert record["_id"] == "report-rpt-001"
        assert "APT29" in record["text"]
        assert record["report_type"] == "tactical"
        assert record["confidence"] == 0.85
        assert "T1195.002" in record["ttps"]

    def test_minimal_record(self):
        record = build_intel_record(
            report_guid="rpt-002",
            summary="Unknown actor phishing campaign",
        )
        assert record["_id"] == "report-rpt-002"
        assert record["threat_actors"] == []
        assert record["ttps"] == []


class TestBuildActorRecord:
    def test_creates_record_from_profile(self):
        profile = {
            "actor_id": "APT29",
            "aliases": ["Cozy Bear"],
            "motivation": "espionage",
            "nation_state": "Russia",
            "known_ttps": [{"technique": "T1566.001"}],
            "targeting": {"sectors": ["government"], "geographies": ["US"]},
        }
        record = build_actor_record(profile)
        assert record["_id"] == "actor-APT29"
        assert "Cozy Bear" in record["text"]
        assert "espionage" in record["text"]


class TestBuildSearchQuery:
    def test_ttp_search(self):
        query = build_search_query(
            query_text="campaigns using T1566 spearphishing",
            top_k=5,
        )
        assert query["query"] == "campaigns using T1566 spearphishing"
        assert query["top_k"] == 5
        assert query["index"] == PINECONE_INDEX

    def test_actor_search_with_filter(self):
        query = build_search_query(
            query_text="APT29 infrastructure",
            top_k=10,
            filter_by={"threat_actors": "APT29"},
        )
        assert query["filter"] == {"threat_actors": "APT29"}

    def test_default_top_k(self):
        query = build_search_query(query_text="test")
        assert query["top_k"] == 5


class TestFormatSearchResults:
    def test_formats_results(self):
        raw_results = [
            {
                "_id": "report-rpt-001",
                "_score": 0.92,
                "text": "APT29 campaign targeting government",
                "report_type": "tactical",
                "date": "2026-02-16",
            },
            {
                "_id": "report-rpt-002",
                "_score": 0.78,
                "text": "Supply chain compromise analysis",
                "report_type": "strategic",
                "date": "2026-02-10",
            },
        ]
        formatted = format_search_results(raw_results)
        assert len(formatted) == 2
        assert formatted[0]["relevance_score"] == 0.92
        assert formatted[0]["id"] == "report-rpt-001"

    def test_empty_results(self):
        assert format_search_results([]) == []
```

**Step 2: Run tests to verify they fail**

Run: `uv run --with pytest python -m pytest tests/test_pinecone_memory.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'lib.pinecone_memory'`

**Step 3: Commit**

```bash
git add tests/test_pinecone_memory.py
git commit -m "test: add Pinecone memory integration tests (red phase)"
```

---

### Task 10: Pinecone Memory Library — Implementation

**Files:**
- Create: `lib/pinecone_memory.py`

**Step 1: Implement Pinecone memory helpers**

```python
"""Pinecone vector memory integration for CTI Agent.

Provides record construction and query formatting for the Pinecone MCP server.
Actual Pinecone operations are performed via MCP tool calls in SKILL.md skills.
This library handles schema construction and result formatting.
"""
from datetime import datetime, timezone

PINECONE_INDEX = "jtia-intel-memory"


def build_intel_record(
    report_guid: str,
    summary: str,
    *,
    report_type: str = "",
    threat_actors: list[str] | None = None,
    ttps: list[str] | None = None,
    ioc_types: list[str] | None = None,
    confidence: float = 0.0,
    campaign: str = "",
) -> dict:
    """Build a Pinecone record from a CTI Agent intelligence report."""
    return {
        "_id": f"report-{report_guid}",
        "text": summary,
        "report_type": report_type,
        "threat_actors": threat_actors or [],
        "ttps": ttps or [],
        "ioc_types": ioc_types or [],
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "confidence": confidence,
        "campaign": campaign,
    }


def build_actor_record(profile: dict) -> dict:
    """Build a Pinecone record from a threat actor profile."""
    text_parts = [
        f"Threat Actor: {profile['actor_id']}",
        f"Aliases: {', '.join(profile.get('aliases', []))}",
        f"Motivation: {profile.get('motivation', 'unknown')}",
        f"Nation State: {profile.get('nation_state', 'unknown')}",
    ]
    ttps = [t["technique"] for t in profile.get("known_ttps", [])]
    if ttps:
        text_parts.append(f"TTPs: {', '.join(ttps)}")
    targeting = profile.get("targeting", {})
    if targeting.get("sectors"):
        text_parts.append(f"Targets: {', '.join(targeting['sectors'])}")

    return {
        "_id": f"actor-{profile['actor_id']}",
        "text": ". ".join(text_parts),
        "threat_actors": [profile["actor_id"]] + profile.get("aliases", []),
        "ttps": ttps,
        "date": profile.get("last_updated", ""),
    }


def build_search_query(
    query_text: str,
    *,
    top_k: int = 5,
    filter_by: dict | None = None,
) -> dict:
    """Build a Pinecone search query for the MCP server."""
    query = {
        "index": PINECONE_INDEX,
        "query": query_text,
        "top_k": top_k,
    }
    if filter_by:
        query["filter"] = filter_by
    return query


def format_search_results(raw_results: list[dict]) -> list[dict]:
    """Format Pinecone search results for use in analysis skills."""
    formatted = []
    for result in raw_results:
        formatted.append({
            "id": result.get("_id", ""),
            "relevance_score": result.get("_score", 0.0),
            "text": result.get("text", ""),
            "report_type": result.get("report_type", ""),
            "date": result.get("date", ""),
        })
    return formatted
```

**Step 2: Run tests to verify they pass**

Run: `uv run --with pytest python -m pytest tests/test_pinecone_memory.py -q`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add lib/pinecone_memory.py
git commit -m "feat: add Pinecone vector memory integration library"
```

---

### Task 11: recall-intelligence SKILL.md

**Files:**
- Create: `skills/recall-intelligence/SKILL.md`

**Step 1: Create skill directory and SKILL.md**

```markdown
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
```

**Step 2: Verify SKILL.md has frontmatter**

Run: `head -3 skills/recall-intelligence/SKILL.md`
Expected: Starts with `---`

**Step 3: Commit**

```bash
git add skills/recall-intelligence/SKILL.md
git commit -m "feat: add recall-intelligence skill for Pinecone memory"
```

---

### Task 12: Update skill_versions.json with New Skills

**Files:**
- Modify: `state/skill_versions.json`

**Step 1: Add new Phase 2+3 skills to version tracker**

Read `state/skill_versions.json`, then add entries for the new skills: `produce-stix-bundle`, `produce-attack-layers`, and `recall-intelligence`. Each gets version 0, status "baseline", matching the existing pattern.

**Step 2: Commit**

```bash
git add state/skill_versions.json
git commit -m "feat: add Phase 2+3 skills to version tracker"
```

---

### Task 13: Update AGENT.md for v2.3.0

**Files:**
- Modify: `AGENT.md`

**Step 1: Update version to 2.3.0**

Change `**Version**: 2.2.0` → `**Version**: 2.3.0`
Change footer `v2.2.0` → `v2.3.0`

**Step 2: Add recall-intelligence to skill registry**

Add after the `produce-attack-layers` row:

```markdown
| `recall-intelligence` | Query Pinecone for historical intelligence context | 4.5 | check-server-health |
```

**Step 3: Add State Files entries**

Add to the State Files table:

```markdown
| `state/confidence_tracker.json` | IOC/assessment freshness tracking | After enrichment |
| `state/metrics.jsonl` | Observability metrics | Every action |
| `actors/{slug}.json` | Persistent threat actor profiles | After analysis |
```

**Step 4: Add Confidence Decay section**

Add a section after the Trust Boundaries:

```markdown
## Confidence Decay

IOC and assessment confidence decays over time using configurable half-lives:

| Type | Half-Life (days) | Rationale |
|------|-----------------|-----------|
| IP address | 30 | Infrastructure rotates fast |
| Domain | 90 | Domains persist longer |
| File hash | 365 | Hashes are immutable |
| URL | 14 | URLs are ephemeral |
| TTP mapping | 730 | TTPs change slowly |
| Actor profile | 365 | Need periodic re-assessment |

**Re-evaluation triggers**: IOC confidence < 0.3 queued for re-enrichment. Actor profiles not updated in 90 days flagged for review. Scanned at session start.
```

**Step 5: Commit**

```bash
git add AGENT.md
git commit -m "feat: update AGENT.md for v2.3.0 with memory, actors, and confidence decay"
```

---

### Task 14: Phase 3 Integration Tests

**Files:**
- Modify: `tests/test_integration.py`

**Step 1: Add Phase 3 test classes**

Add to `tests/test_integration.py`:

```python
class TestConfidenceDecay:
    """Confidence decay calculations work correctly."""

    def test_decay_calculation(self):
        from lib.confidence_decay import calculate_decay
        result = calculate_decay(0.85, days_elapsed=15, half_life_days=30)
        assert 0.3 < result < 0.5

    def test_tracker_state_file_exists(self):
        tracker_file = PROJECT_ROOT / "state" / "confidence_tracker.json"
        assert tracker_file.exists()
        with open(tracker_file) as f:
            data = json.load(f)
        assert "tracked_items" in data


class TestActorProfiles:
    """Actor profile management works correctly."""

    def test_actors_directory_exists(self):
        actors_dir = PROJECT_ROOT / "actors"
        assert actors_dir.is_dir(), "actors/ directory missing"

    def test_create_and_load_profile(self, tmp_path):
        from lib.actor_profiles import create_actor_profile, save_actor_profile, load_actor_profile
        actors_dir = tmp_path / "actors"
        actors_dir.mkdir()
        profile = create_actor_profile(actor_id="TestActor", aliases=["Test"])
        save_actor_profile(profile, actors_dir)
        loaded = load_actor_profile("TestActor", actors_dir)
        assert loaded is not None
        assert loaded["actor_id"] == "TestActor"


class TestMetricsCollection:
    """Metrics collection works correctly."""

    def test_metrics_file_exists(self):
        metrics_file = PROJECT_ROOT / "state" / "metrics.jsonl"
        assert metrics_file.exists()

    def test_create_and_append_metric(self, tmp_path):
        from lib.metrics import create_metric, append_metric, load_metrics
        f = tmp_path / "test_metrics.jsonl"
        metric = create_metric("test-sess", "iocs_enriched", 10)
        append_metric(metric, f)
        loaded = load_metrics(f)
        assert len(loaded) == 1


class TestPineconeMemory:
    """Pinecone memory schema construction works correctly."""

    def test_build_intel_record(self):
        from lib.pinecone_memory import build_intel_record
        record = build_intel_record(
            report_guid="test-001",
            summary="Test report",
            threat_actors=["APT29"],
        )
        assert record["_id"] == "report-test-001"
        assert "APT29" in record["threat_actors"]

    def test_build_search_query(self):
        from lib.pinecone_memory import build_search_query, PINECONE_INDEX
        query = build_search_query("test query", top_k=3)
        assert query["index"] == PINECONE_INDEX
        assert query["top_k"] == 3
```

**Step 2: Update version test**

Change: `assert "**Version**: 2.2.0" in agent_md` → `assert "**Version**: 2.3.0" in agent_md`
Update method name: `test_agent_md_version_is_2_2_0` → `test_agent_md_version_is_2_3_0`

**Step 3: Run all tests**

Run: `uv run --with pytest python -m pytest tests/ -q`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add Phase 3 integration tests"
```

---

### Task 15: Tag v2.3.0

**Files:** None (git operation only)

**Step 1: Run full test suite**

Run: `uv run --with pytest python -m pytest tests/ -q`
Expected: All tests PASS

**Step 2: Run ruff checks**

Run: `ruff check lib/ tests/ --fix && ruff format lib/ tests/`
Expected: Clean

**Step 3: Tag release**

```bash
git tag -a v2.3.0 -m "CTI Agent v2.3.0: Pinecone memory, actor profiles, confidence decay, metrics"
```

**Step 4: Verify tag**

Run: `git tag -l 'v2.*'`
Expected: Shows v2.1.0, v2.2.0, and v2.3.0

---

*Plan complete. 15 tasks covering Pinecone vector memory, recall-intelligence skill, persistent actor profiles, confidence decay engine, metrics collection, and documentation updates.*

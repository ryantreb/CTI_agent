"""Tests for confidence decay calculations."""

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
        result = calculate_decay(
            original_confidence=0.85, days_elapsed=0, half_life_days=30
        )
        assert result == pytest.approx(0.85)

    def test_half_decay_at_half_life(self):
        result = calculate_decay(
            original_confidence=1.0, days_elapsed=30, half_life_days=30
        )
        assert result == pytest.approx(0.1)  # max(0.1, 1 - 30/30) = max(0.1, 0) = 0.1

    def test_partial_decay(self):
        result = calculate_decay(
            original_confidence=0.80, days_elapsed=15, half_life_days=30
        )
        # factor = max(0.1, 1 - 15/30) = max(0.1, 0.5) = 0.5
        assert result == pytest.approx(0.40)

    def test_floor_at_minimum(self):
        result = calculate_decay(
            original_confidence=0.90, days_elapsed=500, half_life_days=30
        )
        assert result == pytest.approx(0.09)  # 0.90 * 0.1 = 0.09

    def test_ip_decay_30_days(self):
        result = calculate_decay(
            original_confidence=0.85, days_elapsed=15, half_life_days=HALF_LIVES["ip"]
        )
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

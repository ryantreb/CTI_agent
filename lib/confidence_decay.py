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

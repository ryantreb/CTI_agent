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

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

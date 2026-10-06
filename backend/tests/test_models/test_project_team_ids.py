"""Project stores team_ids and team_sources as written."""

from app.models.project import Project

_NAME = "demo"


def test_several_owners_survive_construction():
    project = Project(name=_NAME, team_ids=["a", "b", "c"], team_sources={"a": "gitlab", "b": "manual"})

    assert project.team_ids == ["a", "b", "c"]
    assert project.team_sources == {"a": "gitlab", "b": "manual"}


def test_no_team_leaves_the_owners_empty():
    project = Project(name=_NAME)

    assert project.team_ids == []
    assert project.team_sources == {}


def test_a_round_trip_through_mongo_keeps_every_owner():
    """model_dump feeds $set and $setOnInsert, so a derivation would truncate on the way out too."""
    project = Project(name=_NAME, team_ids=["a", "b"], team_sources={"a": "gitlab", "b": "manual"})

    dumped = project.model_dump(by_alias=True)

    assert dumped["team_ids"] == ["a", "b"]
    assert Project(**dumped).team_ids == ["a", "b"]


def test_a_stored_team_id_is_neither_served_nor_written_back():
    """Documents keep the single-owner fields until they are unset, and nothing may read one as an owner."""
    project = Project(name=_NAME, team_id="t-old", team_source="manual", team_ids=["t-new"])

    dumped = project.model_dump(by_alias=True)

    assert "team_id" not in dumped
    assert "team_source" not in dumped
    assert dumped["team_ids"] == ["t-new"]

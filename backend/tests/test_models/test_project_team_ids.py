"""Project stores team_ids and team_sources as written; nothing derives them from the scalars.

Every case here seeds a scalar that disagrees with the stored fields, because that combination is
what a re-introduced derivation would silently rewrite — and what production documents look like
between a team transfer and the migration that follows it.
"""

from app.models.project import Project

_NAME = "demo"


def test_a_stored_list_survives_a_disagreeing_scalar():
    project = Project(name=_NAME, team_id="scalar", team_ids=["stored-a", "stored-b"])

    assert project.team_ids == ["stored-a", "stored-b"]
    assert project.team_id == "scalar"


def test_stored_provenance_survives_a_disagreeing_scalar():
    project = Project(
        name=_NAME,
        team_id="scalar",
        team_source="gitlab",
        team_ids=["stored"],
        team_sources={"stored": "manual"},
    )

    assert project.team_sources == {"stored": "manual"}


def test_several_owners_survive_construction():
    """A list of more than one is the whole point; a derivation from a scalar cannot produce it."""
    project = Project(name=_NAME, team_ids=["a", "b", "c"], team_sources={"a": "gitlab", "b": "manual"})

    assert project.team_ids == ["a", "b", "c"]
    assert project.team_sources == {"a": "gitlab", "b": "manual"}


def test_a_scalar_alone_owns_nothing():
    """The scalar is written for older pods only. It grants no ownership on its own."""
    project = Project(name=_NAME, team_id="t1", team_source="gitlab")

    assert project.team_ids == []
    assert project.team_sources == {}


def test_a_stored_list_outlives_a_cleared_scalar():
    project = Project(name=_NAME, team_id=None, team_source=None, team_ids=["t1"], team_sources={"t1": "gitlab"})

    assert project.team_ids == ["t1"]
    assert project.team_sources == {"t1": "gitlab"}


def test_no_team_leaves_both_shapes_empty():
    project = Project(name=_NAME)

    assert project.team_ids == []
    assert project.team_sources == {}
    assert project.team_id is None
    assert project.team_source is None


def test_a_round_trip_through_mongo_keeps_every_owner():
    """model_dump feeds $set and $setOnInsert, so a derivation would truncate on the way out too."""
    project = Project(name=_NAME, team_ids=["a", "b"], team_sources={"a": "gitlab", "b": "manual"})

    dumped = project.model_dump(by_alias=True)

    assert dumped["team_ids"] == ["a", "b"]
    assert Project(**dumped).team_ids == ["a", "b"]

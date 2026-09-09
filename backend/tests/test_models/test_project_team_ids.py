"""Project derives team_ids from the legacy scalar team fields."""

from app.models.project import Project

_NAME = "demo"


def test_legacy_scalar_is_derived_into_the_list():
    """Documents with the scalar are re-derived into the list on every read."""
    project = Project(name=_NAME, team_id="t1", team_source="gitlab")

    assert project.team_ids == ["t1"]
    assert project.team_sources == {"t1": "gitlab"}


def test_legacy_scalar_without_a_source_derives_the_team_with_no_provenance():
    project = Project(name=_NAME, team_id="t1")

    assert project.team_ids == ["t1"]
    assert project.team_sources == {}


def test_a_stale_stored_list_is_re_derived_from_the_scalar():
    """When both shapes are present, the scalar is the source of truth: a stored list is overwritten."""
    project = Project(name=_NAME, team_id="current", team_ids=["t1", "t2"], team_sources={"t1": "manual"})

    assert project.team_ids == ["current"]
    assert project.team_id == "current"
    assert project.team_sources == {}


def test_no_team_leaves_both_shapes_empty():
    project = Project(name=_NAME)

    assert project.team_ids == []
    assert project.team_sources == {}
    assert project.team_id is None
    assert project.team_source is None


def test_team_source_is_derived_from_the_scalar():
    """Provenance is derived from the scalar team_source, never from a stale dict."""
    project = Project(name=_NAME, team_id="t1", team_source="manual")

    assert project.team_sources == {"t1": "manual"}


def test_unassigned_with_manual_provenance_remains_unassigned():
    """Deliberately unassigned projects with manual provenance stay unassigned."""
    project = Project(name=_NAME, team_id=None, team_source="manual")

    assert project.team_ids == []
    assert project.team_sources == {}

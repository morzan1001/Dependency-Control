"""The expand migration turns the scalar team fields into the multi-team ones."""

from scripts.backfill_project_team_ids import TeamIdsUpdate, plan_team_id_expansion


def test_a_project_with_a_team_and_a_source_expands_to_both_fields():
    plan = plan_team_id_expansion([{"_id": "p1", "team_id": "t1", "team_source": "manual"}])

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=["t1"], team_sources={"t1": "manual"})]


def test_a_project_with_a_team_but_no_source_expands_without_provenance():
    plan = plan_team_id_expansion([{"_id": "p1", "team_id": "t1"}])

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=["t1"], team_sources={})]


def test_a_project_without_a_team_expands_to_an_empty_list():
    """513 of 742 production projects are in this state; they must get [] not a missing field."""
    plan = plan_team_id_expansion([{"_id": "p1", "team_id": None}])

    assert plan == [TeamIdsUpdate(project_id="p1", team_ids=[], team_sources={})]


def test_an_already_migrated_project_is_not_planned_again():
    """The run has to be idempotent: a half-finished migration is re-runnable."""
    plan = plan_team_id_expansion([{"_id": "p1", "team_id": "t1", "team_ids": ["t1"], "team_sources": {"t1": "manual"}}])

    assert plan == []


def test_a_migrated_project_whose_list_disagrees_with_the_scalar_is_left_alone():
    """Phase 3 writers own the list by then; the migration must never clobber their work."""
    plan = plan_team_id_expansion([{"_id": "p1", "team_id": "t1", "team_ids": ["t1", "t2"]}])

    assert plan == []

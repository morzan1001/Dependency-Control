"""Mirrors the update pipelines' $setUnion, whose result the server returns sorted (Percona 8.0.17-6)."""

from app.core.constants import TEAM_SOURCE_MANUAL
from app.repositories.projects import ownership_fields


def test_the_stored_list_is_sorted_whatever_order_the_caller_passes():
    assert ownership_fields(["t-z", "t-a", "t-m"], "gitlab")["team_ids"] == ["t-a", "t-m", "t-z"]


def test_two_callers_disagreeing_only_on_order_insert_the_same_document():
    assert ownership_fields(["t-b", "t-a"], "gitlab") == ownership_fields(["t-a", "t-b"], "gitlab")


def test_a_repeated_owner_is_stored_once():
    fields = ownership_fields(["t-a", "t-a", "t-b"], "github")

    assert fields["team_ids"] == ["t-a", "t-b"]
    assert fields["team_sources"] == {"t-a": "github", "t-b": "github"}


def test_every_owner_is_stamped_with_the_source_that_established_it():
    assert ownership_fields(["t-b", "t-a"], "gitlab")["team_sources"] == {"t-a": "gitlab", "t-b": "gitlab"}


def test_a_project_nobody_owns_stores_the_empty_shapes():
    """[] and {} rather than absent: the one spelling of unassigned every downstream filter uses."""
    assert ownership_fields([], TEAM_SOURCE_MANUAL) == {"team_ids": [], "team_sources": {}}

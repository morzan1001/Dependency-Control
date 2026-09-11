"""The stored ownership a project is inserted with.

``ownership_fields`` is the insert-side counterpart of the ``$setUnion`` the update pipelines use,
and the server returns that operator's result sorted (verified against Percona 8.0.17-6). Inserting
in any other order would have the first sync that touches the project rewrite the list into sorted
order, and the mirrored scalar follows the list's head — so the project would change hands, on a
sync that found nothing new, for no reason a reader could see.
"""

from app.core.constants import TEAM_SOURCE_MANUAL
from app.repositories.projects import ownership_fields


def test_the_stored_list_is_sorted_whatever_order_the_caller_passes():
    assert ownership_fields(["t-z", "t-a", "t-m"], "gitlab")["team_ids"] == ["t-a", "t-m", "t-z"]


def test_the_mirrored_scalar_is_the_head_of_the_sorted_list():
    """Which is the owner ``$setUnion`` would leave at the head, so no sync moves it."""
    assert ownership_fields(["t-z", "t-a"], "github")["team_id"] == "t-a"


def test_two_callers_disagreeing_only_on_order_insert_the_same_document():
    assert ownership_fields(["t-b", "t-a"], "gitlab") == ownership_fields(["t-a", "t-b"], "gitlab")


def test_a_repeated_owner_is_stored_once():
    fields = ownership_fields(["t-a", "t-a", "t-b"], "github")

    assert fields["team_ids"] == ["t-a", "t-b"]
    assert fields["team_sources"] == {"t-a": "github", "t-b": "github"}


def test_every_owner_is_stamped_with_the_source_that_established_it():
    fields = ownership_fields(["t-b", "t-a"], "gitlab")

    assert fields["team_sources"] == {"t-a": "gitlab", "t-b": "gitlab"}
    assert fields["team_source"] == "gitlab"


def test_a_project_nobody_owns_stores_the_empty_shapes_and_no_scalars():
    """``[]`` and ``{}`` rather than absent: that is the one spelling of unassigned everything
    downstream filters on."""
    assert ownership_fields([], TEAM_SOURCE_MANUAL) == {
        "team_ids": [],
        "team_sources": {},
        "team_id": None,
        "team_source": None,
    }

"""Team membership is access to the projects a binding lands, so every writer names what it writes."""

from app.repositories.teams import TeamRepository


def test_no_update_document_reaches_a_team_unread():
    """A pass-through update would let a future caller write a binding past every purpose-built writer's checks."""
    assert not hasattr(TeamRepository, "update_raw")


def test_no_read_matches_teams_by_name():
    """Names are neither unique across instances nor anyone's but the team admin's to set."""
    assert not hasattr(TeamRepository, "get_by_name")
    assert not hasattr(TeamRepository, "find_raw_unbound_for_instance")

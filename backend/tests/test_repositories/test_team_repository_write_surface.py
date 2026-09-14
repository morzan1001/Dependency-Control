"""What a team is reachable through, and what it is deliberately not.

A binding decides which of the estate's projects land in a team, and membership of that team is
access to them. Every writer of one is therefore a method that names what it writes, and no team is
addressable by a name its own admin can set.
"""

from app.repositories.teams import TeamRepository


def test_no_update_document_reaches_a_team_unread():
    """A pass-through update is the one door a future caller writes a binding through without
    passing the checks every purpose-built writer makes."""
    assert not hasattr(TeamRepository, "update_raw")


def test_no_read_matches_teams_by_name():
    """Names are neither unique across instances nor anyone's but the team admin's to set, and
    matching on one is what bound a GitHub group to whichever team was named after it."""
    assert not hasattr(TeamRepository, "get_by_name")
    assert not hasattr(TeamRepository, "find_raw_unbound_for_instance")

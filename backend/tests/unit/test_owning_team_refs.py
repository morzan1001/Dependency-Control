"""A dropped id shows one fewer badge; a kept one would render as a nameless team rather than a gone one."""

import pytest

from app.api.v1.helpers.teams import resolve_team_names, team_refs
from tests.mocks.fake_mongo import FakeDatabase


def _names(refs) -> list[str]:
    return [ref.name for ref in refs]


def test_owners_are_ordered_by_name_not_by_stored_order():
    """The stored order is whatever the last writer's $setUnion left, so it is not shown."""
    refs = team_refs(["t-z", "t-a"], {"t-z": "Zulu", "t-a": "Alpha"})

    assert _names(refs) == ["Alpha", "Zulu"]


def test_owners_are_ordered_by_name_whatever_its_case():
    refs = team_refs(["t-z", "t-a"], {"t-z": "Zulu", "t-a": "alpha"})

    assert _names(refs) == ["alpha", "Zulu"]


def test_two_teams_sharing_a_name_are_ordered_by_id():
    """Without the tie-break the pair would swap between reads and the row would flicker."""
    refs = team_refs(["t-b", "t-a"], {"t-a": "Same", "t-b": "Same"})

    assert [ref.id for ref in refs] == ["t-a", "t-b"]


def test_an_id_the_map_cannot_name_is_dropped():
    """It lost its team between the two reads; showing it would put a nameless badge on the row."""
    refs = team_refs(["t-known", "t-deleted"], {"t-known": "Known"})

    assert [(ref.id, ref.name) for ref in refs] == [("t-known", "Known")]


def test_a_team_stored_without_a_name_is_still_shown():
    """Only an absent entry means gone; an empty name is an unnamed team, and dropping it understates the owners."""
    refs = team_refs(["t-known", "t-unnamed"], {"t-known": "Known", "t-unnamed": ""})

    assert [(ref.id, ref.name) for ref in refs] == [("t-unnamed", ""), ("t-known", "Known")]


def test_no_owners_is_no_rows():
    assert team_refs([], {"t-a": "Alpha"}) == []


@pytest.mark.asyncio
async def test_resolve_team_names_answers_every_id_in_one_read():
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t-a", "name": "Alpha"})
    await db.teams.insert_one({"_id": "t-b", "name": "Bravo"})
    await db.teams.insert_one({"_id": "t-c", "name": "Charlie"})

    assert await resolve_team_names(db, ["t-c", "t-a"]) == {"t-a": "Alpha", "t-c": "Charlie"}


@pytest.mark.asyncio
async def test_resolve_team_names_leaves_out_an_id_no_team_answers():
    """The absence is the signal team_refs drops on; the map must not invent an entry for it."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t-a", "name": "Alpha"})

    assert await resolve_team_names(db, ["t-a", "t-gone"]) == {"t-a": "Alpha"}


@pytest.mark.asyncio
async def test_resolve_team_names_reads_nothing_for_a_page_that_owns_nothing():
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t-a", "name": "Alpha"})

    assert await resolve_team_names(db, []) == {}


@pytest.mark.asyncio
async def test_a_repeated_owner_across_a_page_is_read_once():
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t-a", "name": "Alpha"})

    assert await resolve_team_names(db, ["t-a", "t-a", "t-a"]) == {"t-a": "Alpha"}


@pytest.mark.asyncio
async def test_a_team_stored_without_a_name_resolves_to_the_empty_string():
    """Which is what keeps it distinguishable from an id no team answers."""
    db = FakeDatabase()
    await db.teams.insert_one({"_id": "t-a"})

    assert await resolve_team_names(db, ["t-a"]) == {"t-a": ""}

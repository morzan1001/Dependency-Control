"""A rescan carries created_at = now, so without a lineage guard it always wins the latest-scan slot."""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.constants import MAX_RESCAN_HOPS, SCAN_STATUS_COMPLETED
from app.repositories import ProjectRepository, ScanRepository
from app.services.analysis.engine import _should_update_project_latest_scan
from tests.mocks.fake_mongo import FakeDatabase

_PROJECT_ID = "p1"
_PROJECT_NAME = "proj"
_MAIN_BRANCH = "main"
_FEATURE_BRANCH = "feature/spike"
_TAG_REF = "v1.2.3"
_UNSCANNED_DEFAULT_BRANCH = "trunk"

_HEAD_SCAN_ID = "head"
_RELEASE_SCAN_ID = "release"
_SCHEDULED_RESCAN_ID = "scheduled-rescan"
_MISSING_SCAN_ID = "gone"

_INCOMING_RESCAN_ID = "incoming-rescan"
_INCOMING_INGEST_ID = "incoming-ingest"

_NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)
_LATER = timedelta(hours=1)
_RELEASE_AGE = timedelta(days=30)

# A pointer naming the immediate parent instead of the root, as a chain built before the rescan
# tip target was narrowed to originals carries it.
_PARENT_POINTER_CHAIN = (_HEAD_SCAN_ID, "r1", "r2", "r3")
_DEEPEST_LINK = len(_PARENT_POINTER_CHAIN) - 1
_CYCLE_LEFT = "cycle-left"
_CYCLE_RIGHT = "cycle-right"

_ONLY_THE_CURRENT_LATEST = 1


class _ScanDoc:
    def __init__(self, created_at, is_rescan=False, original_scan_id=None, branch=_MAIN_BRANCH):
        self.created_at = created_at
        self.is_rescan = is_rescan
        self.original_scan_id = original_scan_id
        self.branch = branch


class _CountingScanRepository(ScanRepository):
    """Counts the scan reads the guard makes, so the cheap path stays cheap."""

    def __init__(self, database):
        super().__init__(database)
        self.reads = 0

    async def get_by_id_strong(self, scan_id: str):
        self.reads += 1
        return await super().get_by_id_strong(scan_id)


@pytest.fixture
def db():
    return FakeDatabase()


async def _insert_scan(db, scan_id, created_at, **overrides):
    doc = {
        "_id": scan_id,
        "project_id": _PROJECT_ID,
        "branch": _MAIN_BRANCH,
        "status": SCAN_STATUS_COMPLETED,
        "created_at": created_at,
    }
    doc.update(overrides)
    await db.scans.insert_one(doc)


async def _seed(db, latest_scan_id):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": _PROJECT_NAME, "latest_scan_id": latest_scan_id})
    await _insert_scan(db, _HEAD_SCAN_ID, _NOW)
    await _insert_scan(db, _RELEASE_SCAN_ID, _NOW - _RELEASE_AGE)


async def _decide(db, scan_id, scan_doc, scan_repo=None):
    return await _should_update_project_latest_scan(
        scan_id, scan_doc, _PROJECT_ID, scan_repo or ScanRepository(db), ProjectRepository(db)
    )


async def _seed_parent_pointer_chain(db, depth):
    """A chain whose links name their immediate parent, with the project pointing at link `depth`."""
    await db.projects.insert_one(
        {"_id": _PROJECT_ID, "name": _PROJECT_NAME, "latest_scan_id": _PARENT_POINTER_CHAIN[depth]}
    )
    await _insert_scan(db, _RELEASE_SCAN_ID, _NOW - _RELEASE_AGE)
    for index, scan_id in enumerate(_PARENT_POINTER_CHAIN):
        lineage = (
            {"is_rescan": True, "original_scan_id": _PARENT_POINTER_CHAIN[index - 1]} if index else {"is_rescan": False}
        )
        await _insert_scan(db, scan_id, _NOW + index * _LATER, **lineage)


@pytest.mark.asyncio
async def test_a_rescan_of_the_current_latest_still_updates_it(db):
    await _seed(db, _HEAD_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_rescan_of_the_release_does_not_hijack_the_project_tile(db):
    await _seed(db, _HEAD_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=_RELEASE_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is False


@pytest.mark.asyncio
async def test_a_manual_rescan_wins_the_slot_when_the_latest_is_a_scheduled_rescan_of_the_same_original(db):
    """Both sides reduce to their lineage root, so the manual endpoint's root-valued
    original_scan_id matches a latest that is itself a rescan."""
    await _seed(db, _SCHEDULED_RESCAN_ID)
    await _insert_scan(db, _SCHEDULED_RESCAN_ID, _NOW + _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + 2 * _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_rescan_with_no_recorded_lineage_is_judged_on_its_created_at_alone(db):
    await _seed(db, _RELEASE_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=None)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_fresh_ingest_wins_the_slot_even_when_it_carries_a_lineage_field(db):
    await _seed(db, _RELEASE_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=False, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_INGEST_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_rescan_of_another_lineage_wins_the_slot_when_latest_scan_id_dangles(db):
    """A latest_scan_id pointing at a deleted scan names no lineage the guard could protect,
    so re-anchoring on a live scan beats holding a pointer into nothing."""
    await _seed(db, _MISSING_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=_RELEASE_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_rescan_is_still_accepted_when_the_project_has_no_latest_scan(db):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": _PROJECT_NAME, "latest_scan_id": None})
    scan_doc = _ScanDoc(_NOW, is_rescan=True, original_scan_id=_MISSING_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("depth", range(len(_PARENT_POINTER_CHAIN)))
async def test_a_tip_rescan_takes_the_slot_at_every_depth_of_a_parent_pointer_chain(db, depth):
    """Without the walk the project freezes on its pre-deploy numbers for good: the incoming root
    never changes, so every later interval is discarded the same way."""
    await _seed_parent_pointer_chain(db, depth)
    scan_doc = _ScanDoc(_NOW + len(_PARENT_POINTER_CHAIN) * _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_release_rescan_is_still_refused_against_a_parent_pointer_chain(db):
    await _seed_parent_pointer_chain(db, _DEEPEST_LINK)
    scan_doc = _ScanDoc(_NOW + len(_PARENT_POINTER_CHAIN) * _LATER, is_rescan=True, original_scan_id=_RELEASE_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc) is False


@pytest.mark.asyncio
async def test_a_rescan_of_the_current_latest_reads_nothing_beyond_it(db):
    await _seed_parent_pointer_chain(db, _DEEPEST_LINK)
    scan_repo = _CountingScanRepository(db)
    scan_doc = _ScanDoc(
        _NOW + len(_PARENT_POINTER_CHAIN) * _LATER,
        is_rescan=True,
        original_scan_id=_PARENT_POINTER_CHAIN[_DEEPEST_LINK - 1],
    )

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc, scan_repo) is True
    assert scan_repo.reads == _ONLY_THE_CURRENT_LATEST


async def _seed_with_default_branch(db, default_branch):
    await db.projects.insert_one(
        {
            "_id": _PROJECT_ID,
            "name": _PROJECT_NAME,
            "latest_scan_id": _HEAD_SCAN_ID,
            "default_branch": default_branch,
        }
    )
    await _insert_scan(db, _HEAD_SCAN_ID, _NOW)


@pytest.mark.asyncio
async def test_a_feature_branch_scan_does_not_take_the_head_slot_from_the_default_branch(db):
    """The slot answers "what is on main"; a feature pipeline finishing later answers something else,
    and letting it in makes a delta against head report main's findings as removed."""
    await _seed_with_default_branch(db, _MAIN_BRANCH)
    scan_doc = _ScanDoc(_NOW + _LATER, branch=_FEATURE_BRANCH)

    assert await _decide(db, _INCOMING_INGEST_ID, scan_doc) is False


@pytest.mark.asyncio
async def test_a_tag_build_does_not_take_the_head_slot(db):
    await _seed_with_default_branch(db, _MAIN_BRANCH)
    scan_doc = _ScanDoc(_NOW + _LATER, branch=_TAG_REF)

    assert await _decide(db, _INCOMING_INGEST_ID, scan_doc) is False


@pytest.mark.asyncio
async def test_a_newer_scan_on_the_default_branch_still_takes_the_slot(db):
    await _seed_with_default_branch(db, _MAIN_BRANCH)
    scan_doc = _ScanDoc(_NOW + _LATER, branch=_MAIN_BRANCH)

    assert await _decide(db, _INCOMING_INGEST_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_project_with_no_known_default_branch_keeps_the_created_at_rule(db):
    """Without VCS integration nothing says which branch is the tip, so recency decides as before."""
    await _seed(db, _HEAD_SCAN_ID)
    scan_doc = _ScanDoc(_NOW + _LATER, branch=_FEATURE_BRANCH)

    assert await _decide(db, _INCOMING_INGEST_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_branch_scan_still_wins_when_the_current_latest_is_not_on_the_default_branch(db):
    """CI wired to one branch while the VCS default is another: the slot follows recency there, or
    nothing would ever update it."""
    await _seed_with_default_branch(db, _UNSCANNED_DEFAULT_BRANCH)
    scan_doc = _ScanDoc(_NOW + _LATER, branch=_FEATURE_BRANCH)

    assert await _decide(db, _INCOMING_INGEST_ID, scan_doc) is True


@pytest.mark.asyncio
async def test_a_lineage_that_points_at_itself_in_a_cycle_is_decided_rather_than_walked_forever(db):
    await db.projects.insert_one({"_id": _PROJECT_ID, "name": _PROJECT_NAME, "latest_scan_id": _CYCLE_LEFT})
    await _insert_scan(db, _CYCLE_LEFT, _NOW, is_rescan=True, original_scan_id=_CYCLE_RIGHT)
    await _insert_scan(db, _CYCLE_RIGHT, _NOW, is_rescan=True, original_scan_id=_CYCLE_LEFT)
    scan_repo = _CountingScanRepository(db)
    scan_doc = _ScanDoc(_NOW + _LATER, is_rescan=True, original_scan_id=_HEAD_SCAN_ID)

    assert await _decide(db, _INCOMING_RESCAN_ID, scan_doc, scan_repo) is False
    assert scan_repo.reads <= _ONLY_THE_CURRENT_LATEST + 2 * MAX_RESCAN_HOPS

"""Two chat answers that read as complete: a breakdown over a closed domain, and a top-N sample.

A breakdown bounded below the number of buckets it groups over drops some of them under a key
named "breakdown", and the counts silently stop adding up to the total. A ranked sample with no
population beside it reads as the whole list of offenders.
"""

import pytest

from app.models.finding import FindingType, Severity
from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools.crypto_tools import _NOISY_RULE_SAMPLE, suggest_crypto_policy_override
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_CALLER = "u-breakdown"
_PROJECT = "p-breakdown"
_SCAN = "s-breakdown"
_MORE_RULES_THAN_SHOWN = _NOISY_RULE_SAMPLE + 4
_FINDINGS_PER_RULE = 2


def _caller() -> User:
    return User(
        _id=_CALLER,
        username="breakdown-caller",
        email="breakdown@example.com",
        permissions=list(PRESET_ADMIN),
    )


def _seed_project(db: FakeDatabase) -> None:
    db.projects._docs[_PROJECT] = {
        "_id": _PROJECT,
        "name": "breakdown-project",
        "members": [{"user_id": _CALLER, "role": "owner"}],
    }
    db.scans._docs[_SCAN] = {
        "_id": _SCAN,
        "project_id": _PROJECT,
        "status": "completed",
        "created_at": "2026-09-01T00:00:00Z",
    }


def _seed_one_finding_per_type(db: FakeDatabase) -> None:
    for index, finding_type in enumerate(FindingType):
        db.findings._docs[f"f{index}"] = {
            "_id": f"f{index}",
            "project_id": _PROJECT,
            "scan_id": _SCAN,
            "type": finding_type.value,
            "severity": Severity.HIGH.value,
        }


@pytest.mark.asyncio
async def test_the_type_breakdown_holds_every_type_the_scan_carries():
    db = FakeDatabase()
    _seed_project(db)
    _seed_one_finding_per_type(db)

    result = await ChatToolRegistry().execute_tool(
        "get_findings_by_type", {"project_id": _PROJECT}, _caller(), db
    )

    assert len(result["breakdown"]) == len(FindingType)


@pytest.mark.asyncio
async def test_the_severity_breakdown_holds_every_severity_the_scan_carries():
    db = FakeDatabase()
    _seed_project(db)
    for index, severity in enumerate(Severity):
        db.findings._docs[f"f{index}"] = {
            "_id": f"f{index}",
            "project_id": _PROJECT,
            "scan_id": _SCAN,
            "type": FindingType.VULNERABILITY.value,
            "severity": severity.value,
        }

    result = await ChatToolRegistry().execute_tool(
        "get_findings_by_severity", {"project_id": _PROJECT}, _caller(), db
    )

    assert len(result["breakdown"]) == len(Severity)


@pytest.mark.asyncio
async def test_the_noisy_rule_sample_names_how_many_rules_there_are():
    db = FakeDatabase()
    for rule in range(_MORE_RULES_THAN_SHOWN):
        for occurrence in range(_FINDINGS_PER_RULE):
            key = f"r{rule}-{occurrence}"
            db.findings._docs[key] = {
                "_id": key,
                "project_id": _PROJECT,
                "scan_id": _SCAN,
                "type": FindingType.CRYPTO_WEAK_ALGORITHM.value,
                "details": {"rule_id": f"rule-{rule:02d}"},
            }

    result = await suggest_crypto_policy_override(db, project_id=_PROJECT, scan_id=_SCAN)

    assert len(result["top_noisy_rules"]) == _NOISY_RULE_SAMPLE
    assert result["top_noisy_rules_total"] == _MORE_RULES_THAN_SHOWN


@pytest.mark.asyncio
async def test_a_scan_with_no_crypto_findings_reports_an_empty_population():
    db = FakeDatabase()

    result = await suggest_crypto_policy_override(db, project_id=_PROJECT, scan_id=_SCAN)

    assert result["top_noisy_rules"] == []
    assert result["top_noisy_rules_total"] == 0

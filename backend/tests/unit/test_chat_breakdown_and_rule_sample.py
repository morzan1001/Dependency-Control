"""Two chat answers that read as complete: a breakdown over a closed domain, and a top-N sample.

A breakdown bounded below the number of buckets it groups over drops some of them under a key
named "breakdown", and the counts silently stop adding up to the total. A ranked sample with no
population beside it reads as the whole list of offenders.
"""

import json
from pathlib import Path

import pytest

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.models.user import User
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoRule
from app.schemas.policy_audit import PolicyAuditAction
from app.services.analyzers.crypto.base import crypto_findings_for_assets
from app.services.chat.tools import ChatToolRegistry
from app.services.chat.tools.crypto_tools import _NOISY_RULE_SAMPLE, suggest_crypto_policy_override
from app.services.crypto_policy.seeder import load_seed_rules, seed_crypto_policies, write_policy
from app.services.normalizers.sast import _parse_opengrep_item
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_CALLER = "u-breakdown"
_PROJECT = "p-breakdown"
_SCAN = "s-breakdown"
_MORE_RULES_THAN_SHOWN = _NOISY_RULE_SAMPLE + 4
_FINDINGS_PER_RULE = 2
_LOUDEST_RULE = "rule-zz"
_FINDINGS_FOR_LOUDEST = _FINDINGS_PER_RULE + 1


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


_EVERY_SEED_RULE_ENABLED = [rule.model_copy(update={"enabled": True}) for rule in load_seed_rules()]


async def _system_policy(db: FakeDatabase, rules: list[CryptoRule]) -> None:
    await write_policy(db, scope="system", project_id=None, rules=rules, action=PolicyAuditAction.SEED, actor=None)


def _rules_named(rule_ids: list[str]) -> list[CryptoRule]:
    return [_EVERY_SEED_RULE_ENABLED[0].model_copy(update={"rule_id": rule_id}) for rule_id in rule_ids]


def _md5_finding() -> dict:
    md5 = CryptoAsset(
        project_id=_PROJECT,
        scan_id=_SCAN,
        bom_ref="crypto/algorithm/md5",
        name="MD5",
        asset_type=CryptoAssetType.ALGORITHM,
        primitive=CryptoPrimitive.HASH,
    )
    (finding,) = crypto_findings_for_assets([md5], _EVERY_SEED_RULE_ENABLED, scanner="crypto_weak_algorithm")
    return {**finding, "_id": finding["id"], "project_id": _PROJECT, "scan_id": _SCAN}


def _crypto_finding(key: str, rule_id: str) -> dict:
    return {
        "_id": key,
        "project_id": _PROJECT,
        "scan_id": _SCAN,
        "type": FindingType.CRYPTO_WEAK_ALGORITHM.value,
        "details": {"rule_id": rule_id},
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

    result = await ChatToolRegistry().execute_tool("get_findings_by_type", {"project_id": _PROJECT}, _caller(), db)

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

    result = await ChatToolRegistry().execute_tool("get_findings_by_severity", {"project_id": _PROJECT}, _caller(), db)

    assert len(result["breakdown"]) == len(Severity)


@pytest.mark.asyncio
async def test_the_noisy_rule_sample_names_how_many_rules_there_are():
    db = FakeDatabase()
    await _system_policy(db, _rules_named([f"rule-{rule:02d}" for rule in range(_MORE_RULES_THAN_SHOWN)]))
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
async def test_rules_tied_on_findings_are_sampled_by_rule_id():
    db = FakeDatabase()
    await _system_policy(
        db, _rules_named([_LOUDEST_RULE, *(f"rule-{rule:02d}" for rule in range(_MORE_RULES_THAN_SHOWN))])
    )
    for occurrence in range(_FINDINGS_FOR_LOUDEST):
        key = f"loud-{occurrence}"
        db.findings._docs[key] = _crypto_finding(key, _LOUDEST_RULE)
    # Seeded against rule-id order so collection order cannot stand in for the tiebreak.
    for rule in reversed(range(_MORE_RULES_THAN_SHOWN)):
        for occurrence in range(_FINDINGS_PER_RULE):
            key = f"r{rule}-{occurrence}"
            db.findings._docs[key] = _crypto_finding(key, f"rule-{rule:02d}")

    result = await suggest_crypto_policy_override(db, project_id=_PROJECT, scan_id=_SCAN)

    tied_shown = _NOISY_RULE_SAMPLE - 1
    assert [row["rule_id"] for row in result["top_noisy_rules"]] == [
        _LOUDEST_RULE,
        *[f"rule-{rule:02d}" for rule in range(tied_shown)],
    ]


@pytest.mark.asyncio
async def test_a_scan_with_no_crypto_findings_reports_an_empty_population():
    db = FakeDatabase()
    await seed_crypto_policies(db)

    result = await suggest_crypto_policy_override(db, project_id=_PROJECT, scan_id=_SCAN)

    assert result["top_noisy_rules"] == []
    assert result["top_noisy_rules_total"] == 0


@pytest.mark.asyncio
async def test_the_noisy_rule_sample_counts_every_rule_a_finding_matched():
    """Disabling a finding's lead rule leaves it standing under the other rules it matched."""
    db = FakeDatabase()
    await _system_policy(db, _EVERY_SEED_RULE_ENABLED)
    finding = _md5_finding()
    db.findings._docs[finding["_id"]] = finding
    matched = sorted(entry["rule_id"] for entry in finding["details"]["matched_rules"])

    result = await suggest_crypto_policy_override(db, project_id=_PROJECT, scan_id=_SCAN)

    assert len(matched) > 1
    assert result["top_noisy_rules"] == [{"rule_id": rule_id, "findings": 1} for rule_id in matched]
    assert result["top_noisy_rules_total"] == len(matched)


@pytest.mark.asyncio
async def test_the_noisy_rule_sample_names_only_rules_the_policy_enables():
    """A disabled rule or a SAST check id is no rule a project override could switch off."""
    db = FakeDatabase()
    await _system_policy(db, _EVERY_SEED_RULE_ENABLED)
    finding = _md5_finding()
    db.findings._docs[finding["_id"]] = finding
    fixture = Path(__file__).parents[1] / "fixtures" / "sast" / "crypto_misuse_findings.json"
    sast = _parse_opengrep_item(json.loads(fixture.read_text())["results"][0]).model_dump()
    db.findings._docs[sast["id"]] = {**sast, "_id": sast["id"], "project_id": _PROJECT, "scan_id": _SCAN}
    disabled, *still_enabled = sorted(entry["rule_id"] for entry in finding["details"]["matched_rules"])
    rule = next(r for r in _EVERY_SEED_RULE_ENABLED if r.rule_id == disabled)
    await write_policy(
        db,
        scope="project",
        project_id=_PROJECT,
        rules=[rule.model_copy(update={"enabled": False})],
        action=PolicyAuditAction.UPDATE,
        actor=None,
    )

    result = await suggest_crypto_policy_override(db, project_id=_PROJECT, scan_id=_SCAN)

    assert sast["type"] == FindingType.CRYPTO_KEY_MANAGEMENT.value
    assert result["top_noisy_rules"] == [{"rule_id": rule_id, "findings": 1} for rule_id in still_enabled]

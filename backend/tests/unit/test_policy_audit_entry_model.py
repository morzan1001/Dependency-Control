from datetime import datetime, timezone

from app.models.policy_audit_entry import PolicyAuditEntry
from app.schemas.policy_audit import PolicyAuditAction


def test_audit_entry_minimal():
    entry = PolicyAuditEntry(
        policy_scope="system",
        project_id=None,
        version=1,
        action=PolicyAuditAction.SEED,
        actor_user_id=None,
        actor_display_name=None,
        timestamp=datetime.now(timezone.utc),
        snapshot={"scope": "system", "rules": []},
        change_summary="Initial policy (0 rules)",
        comment=None,
    )
    assert entry.policy_scope == "system"
    assert entry.action == PolicyAuditAction.SEED
    assert entry.id


def test_audit_entry_project_scope():
    entry = PolicyAuditEntry(
        policy_scope="project",
        project_id="p1",
        version=3,
        action=PolicyAuditAction.UPDATE,
        actor_user_id="u1",
        actor_display_name="alice",
        timestamp=datetime.now(timezone.utc),
        snapshot={"scope": "project", "project_id": "p1", "rules": []},
        change_summary="Toggled enabled on 1",
        comment="Q2 audit",
    )
    assert entry.project_id == "p1"
    assert entry.comment == "Q2 audit"


def test_action_enum_values():
    assert PolicyAuditAction.CREATE.value == "create"
    assert PolicyAuditAction.UPDATE.value == "update"
    assert PolicyAuditAction.DELETE.value == "delete"
    assert PolicyAuditAction.REVERT.value == "revert"
    assert PolicyAuditAction.SEED.value == "seed"


def test_audit_entry_populate_by_name_alias():
    data = {
        "_id": "abc",
        "policy_scope": "system",
        "version": 1,
        "action": "seed",
        "timestamp": datetime.now(timezone.utc),
        "snapshot": {},
        "change_summary": "x",
    }
    entry = PolicyAuditEntry.model_validate(data)
    assert entry.id == "abc"
    dumped = entry.model_dump(by_alias=True)
    assert dumped["_id"] == "abc"

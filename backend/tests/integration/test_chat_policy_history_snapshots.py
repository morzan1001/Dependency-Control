"""A policy snapshot is the whole policy, which the chat history answer never shows."""

import bson
import pytest

from app.models.policy_audit_entry import PolicyAuditEntry
from app.schemas.policy_audit import PolicyAuditAction
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.auth import make_admin
from tests.helpers.profiler import profiled

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_SNAPSHOT = {"rules": [{"rule_id": f"rule-{i}", "description": "x" * 200} for i in range(100)]}


async def test_the_chat_policy_history_leaves_every_snapshot_on_the_server(db):
    await db.crypto_policy_history.insert_many(
        [
            PolicyAuditEntry(
                policy_scope="system",
                version=version,
                action=PolicyAuditAction.UPDATE,
                snapshot=_SNAPSHOT,
                change_summary=f"v{version}",
            ).model_dump(by_alias=True)
            for version in (1, 2, 3)
        ]
    )

    result, entries = await profiled(
        db, ChatToolRegistry().execute_tool("list_policy_audit_entries", {"policy_scope": "system"}, make_admin(), db)
    )

    assert [e["change_summary"] for e in result["entries"]] == ["v3", "v2", "v1"]
    reads = [e for e in entries if e["ns"].endswith(".crypto_policy_history") and e["op"] == "query"]
    assert reads
    assert sum(e["responseLength"] for e in reads) < len(bson.encode(_SNAPSHOT))

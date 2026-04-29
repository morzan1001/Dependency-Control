"""Unit tests for the crypto-asset MCP tool functions.

These standalone async functions live in app.services.chat.tools and are
callable directly (without going through ChatToolRegistry) — useful both for
unit testing and for future callers that want to invoke them outside the
chat-tool dispatch path.
"""

from unittest.mock import MagicMock

import pytest

from tests.mocks.mongodb import create_mock_collection


def _make_mock_db(collection):
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return db


@pytest.mark.asyncio
async def test_mcp_list_crypto_assets():
    from app.services.chat.tools import list_crypto_assets

    asset_doc = {
        "_id": "r",
        "project_id": "p",
        "scan_id": "s",
        "bom_ref": "r",
        "name": "MD5",
        "asset_type": "algorithm",
    }
    mock_col = create_mock_collection(find=[asset_doc], count_documents=1)
    db = _make_mock_db(mock_col)

    result = await list_crypto_assets(db, project_id="p", scan_id="s", limit=50)
    assert result["total"] >= 1
    assert any(i["name"] == "MD5" for i in result["items"])


@pytest.mark.asyncio
async def test_mcp_get_crypto_summary():
    from app.services.chat.tools import get_crypto_summary

    agg_results = [{"_id": "algorithm", "count": 1}]
    mock_col = create_mock_collection(aggregate=agg_results, count_documents=1)
    db = _make_mock_db(mock_col)

    result = await get_crypto_summary(db, project_id="p2", scan_id="s2")
    assert result["total"] == 1
    assert "by_type" in result

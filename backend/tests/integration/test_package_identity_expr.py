"""The aggregation twin of package_identity has to agree with the Python function on the server
itself: FakeDatabase evaluates $regexFind with Python's engine, the server with PCRE."""

import pytest

from app.core.purl import package_identity_expr
from tests.test_core.test_purl import _IDENTITY_TABLE


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_the_server_computes_every_identity_of_the_table(db):
    rows = [
        {"_id": index, **dict(zip(("purl", "name", "type", "group"), param.values[:4], strict=True))}
        for index, param in enumerate(_IDENTITY_TABLE)
    ]
    await db.dependencies.insert_many(rows)

    computed = await db.dependencies.aggregate(
        [{"$project": {"identity": package_identity_expr()}}, {"$sort": {"_id": 1}}]
    ).to_list(None)

    assert [(row["identity"]["type"], row["identity"]["path"]) for row in computed] == [
        param.values[4] for param in _IDENTITY_TABLE
    ]

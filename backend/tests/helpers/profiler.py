"""What the server ran for one awaited call, read from MongoDB's profiler on a test's own database."""

from collections.abc import Awaitable
from typing import Any

_PROFILE_BYTES = 64 * 1024 * 1024


async def profiled[T](db, call: Awaitable[T]) -> tuple[T, list[dict[str, Any]]]:
    """The result of ``call`` and every operation the server ran on ``db`` meanwhile."""
    await db["system.profile"].drop()
    # The server's default 1 MiB profile collection evicts the first operations of a call that writes a lot.
    await db.create_collection("system.profile", capped=True, size=_PROFILE_BYTES)
    # The level alone: slowms is server-wide and would log every operation of every database.
    await db.command("profile", 2)
    try:
        result = await call
    finally:
        await db.command("profile", 0)
    return result, await db["system.profile"].find().to_list(None)


def inserts_and_upserts(entries: list[dict[str, Any]], collection: str) -> tuple[int, int]:
    """(insert commands, upserting updates) run on ``collection``."""
    ops = [entry for entry in entries if entry["ns"].endswith(f".{collection}")]
    inserts = sum(1 for op in ops if op["op"] == "insert")
    return inserts, sum(1 for op in ops if op["op"] == "update" and op["command"].get("upsert"))

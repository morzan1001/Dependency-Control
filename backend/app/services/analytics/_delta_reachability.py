"""Per-side reachability label shared by the scan-delta services.

Every service that builds a ScanDeltaResponse labels its own sides, so a path that bypasses
the orchestrator (chat tools, MCP) cannot emit an unlabelled envelope.
"""

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.schemas.scan_delta import ScanDeltaReachability

_REACHABILITY_PATH = "stats.reachability"
_UNREPORTED_COUNT = 0


async def side_reachability(db: AsyncIOMotorDatabase, scan_id: str) -> ScanDeltaReachability | None:
    """Coverage of one side, or None when that scan reports no reachability at all."""
    doc = await db["scans"].find_one({"_id": scan_id}, {_REACHABILITY_PATH: 1})
    reach = ((doc or {}).get("stats") or {}).get("reachability")
    if not reach:
        return None
    return ScanDeltaReachability(
        coverable_count=reach.get("coverable_count", _UNREPORTED_COUNT),
        analyzed_count=reach.get("analyzed_count", _UNREPORTED_COUNT),
    )

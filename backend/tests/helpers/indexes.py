"""The indexes reads over every head scan hint, for live tests that do not build every index."""

from app.core.constants import DEPENDENCIES_SCAN_PACKAGE_INDEX, FINDINGS_SCAN_COMPONENT_INDEX, FINDINGS_SCAN_TYPE_INDEX


async def create_hinted_indexes(db) -> None:
    """A hinted read fails on a database without its index."""
    await db.findings.create_index(FINDINGS_SCAN_TYPE_INDEX)
    await db.findings.create_index(FINDINGS_SCAN_COMPONENT_INDEX)
    await db.dependencies.create_index(DEPENDENCIES_SCAN_PACKAGE_INDEX)

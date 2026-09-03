"""MongoDB access for releases."""

from app.core.metrics import track_db_operation
from app.models.release import Release
from app.repositories.base import BaseRepository


class ReleaseRepository(BaseRepository[Release]):
    collection_name = "releases"
    model_class = Release

    async def record(self, release: Release) -> None:
        """Keyed on (project_id, environment, scan_id): a CI retry or a re-deploy of the same artefact
        refreshes one record, while a rollback to an older scan is a distinct one that wins on released_at."""
        key = {
            "project_id": release.project_id,
            "environment": release.environment,
            "scan_id": release.scan_id,
        }
        with track_db_operation(self.collection_name, "update_one"):
            await self.collection.update_one(
                key,
                {
                    "$set": {"version": release.version, "released_at": release.released_at},
                    "$setOnInsert": {"_id": release.id},
                },
                upsert=True,
            )

from app.repositories.projections import ProjectWithScanId


def projections(project_ids: list[str]) -> list[ProjectWithScanId]:
    return [ProjectWithScanId(id=project_id, name=project_id) for project_id in project_ids]

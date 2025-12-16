from fastapi import APIRouter, Depends, Query
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api import deps
from app.models.user import User
from app.db.mongodb import get_database

router = APIRouter()

@router.get("/dependencies", summary="Search for dependencies across projects")
async def search_dependencies(
    q: str = Query(..., min_length=3, description="Package name to search for"),
    version: str = Query(None, description="Specific version"),
    current_user: User = Depends(deps.get_current_active_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    """
    Search for dependencies in the latest scans of all projects the user has access to.
    Optimized to use 'latest_scan_id' from Project document to avoid expensive aggregation.
    """
    # 1. Get list of project IDs user has access to
    
    if "*" not in current_user.permissions:
        # Find teams where user is a member
        user_teams = await db.teams.find({"members.user_id": str(current_user.id)}, {"_id": 1}).to_list(1000)
        user_team_ids = [str(t["_id"]) for t in user_teams]

        # Find projects where user is member or owner OR project is assigned to one of user's teams
        user_projects_cursor = db.projects.find(
            {
                "$or": [
                    {"owner_id": str(current_user.id)},
                    {"members.user_id": str(current_user.id)},
                    {"team_id": {"$in": user_team_ids}}
                ]
            },
            {"_id": 1, "latest_scan_id": 1, "name": 1}
        )
    else:
        user_projects_cursor = db.projects.find({}, {"_id": 1, "latest_scan_id": 1, "name": 1})

    user_projects = await user_projects_cursor.to_list(10000)
    
    # Map project_id to project_name for enrichment later
    project_map = {p["_id"]: p.get("name", "Unknown") for p in user_projects}
    
    # Filter out projects that have no scan yet
    latest_scan_ids = [p["latest_scan_id"] for p in user_projects if p.get("latest_scan_id")]
    
    if not latest_scan_ids:
        return []

    # 2. Query the normalized 'dependencies' collection
    # This is much faster than aggregating over the 'scans' collection
    
    query = {
        "scan_id": {"$in": latest_scan_ids},
        "name": {"$regex": q, "$options": "i"}
    }
    if version:
        query["version"] = version
        
    dependencies = await db.dependencies.find(query).limit(100).to_list(100)
    
    # Enrich with project names
    enriched_results = []
    for dep in dependencies:
        enriched_results.append({
            "project_name": project_map.get(dep["project_id"], "Unknown"),
            "project_id": dep["project_id"],
            "component": {
                "name": dep["name"],
                "version": dep["version"],
                "purl": dep["purl"],
                "type": dep["type"],
                "licenses": [dep.get("license")] if dep.get("license") else []
            },
            "scan_date": dep["created_at"]
        })
            
    return enriched_results

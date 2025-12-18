from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import uuid

class Dependency(BaseModel):
    """
    Represents a flattened dependency for efficient searching and analytics.
    This is a 'derived' record from the raw SBOM.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan where this was found")
    
    # Core Identity
    name: str
    version: str
    purl: str = Field(..., description="Package URL (unique identifier)")
    type: str = Field(..., description="e.g. maven, npm, pypi")
    
    # Metadata
    license: Optional[str] = None
    scope: Optional[str] = None # runtime, dev, etc.
    
    # Graph info
    direct: bool = False
    parent_components: List[str] = Field(default_factory=list, description="List of parent component IDs/names")
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
        indexes = [
            # These would be created in init_db.py
            # ("project_id", 1),
            # ("scan_id", 1),
            # ("name", 1),
            # ("purl", 1)
        ]

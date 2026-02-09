"""
Invitation Repository

Centralizes all database operations for invitations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.invitation import ProjectInvitation, SystemInvitation


class InvitationRepository:
    """Repository for invitation database operations."""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.project_invitations = db.invitations
        self.system_invitations = db.system_invitations

    # Project Invitations
    async def get_project_invitation(self, invitation_id: str) -> Optional[Dict[str, Any]]:
        """Get project invitation by ID."""
        return await self.project_invitations.find_one({"_id": invitation_id})

    async def get_project_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get project invitation by token."""
        return await self.project_invitations.find_one({"token": token})

    async def create_project_invitation(self, invitation: ProjectInvitation) -> ProjectInvitation:
        """Create a new project invitation."""
        await self.project_invitations.insert_one(invitation.model_dump(by_alias=True))
        return invitation

    async def delete_project_invitation(self, invitation_id: str) -> bool:
        """Delete project invitation by ID."""
        result = await self.project_invitations.delete_one({"_id": invitation_id})
        return result.deleted_count > 0

    async def find_project_invitations(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Find invitations for a project."""
        cursor = self.project_invitations.find({"project_id": project_id}).skip(skip).limit(limit)
        return await cursor.to_list(limit)

    async def delete_project_invitations_by_project(self, project_id: str) -> int:
        """Delete all invitations for a project."""
        result = await self.project_invitations.delete_many({"project_id": project_id})
        return result.deleted_count

    # System Invitations
    async def get_system_invitation(self, invitation_id: str) -> Optional[Dict[str, Any]]:
        """Get system invitation by ID."""
        return await self.system_invitations.find_one({"_id": invitation_id})

    async def get_system_invitation_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get active system invitation by token (non-used, non-expired)."""
        return await self.system_invitations.find_one(
            {
                "token": token,
                "is_used": False,
                "expires_at": {"$gt": datetime.now(timezone.utc)},
            }
        )

    async def get_system_invitation_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get active system invitation by email (non-used, non-expired)."""
        return await self.system_invitations.find_one(
            {
                "email": email,
                "is_used": False,
                "expires_at": {"$gt": datetime.now(timezone.utc)},
            }
        )

    async def create_system_invitation(self, invitation: SystemInvitation) -> SystemInvitation:
        """Create a new system invitation."""
        await self.system_invitations.insert_one(invitation.model_dump(by_alias=True))
        return invitation

    async def update_system_invitation(self, invitation_id: str, update_data: Dict[str, Any]) -> None:
        """Update system invitation by ID."""
        await self.system_invitations.update_one({"_id": invitation_id}, {"$set": update_data})

    async def delete_system_invitation(self, invitation_id: str) -> bool:
        """Delete system invitation by ID."""
        result = await self.system_invitations.delete_one({"_id": invitation_id})
        return result.deleted_count > 0

    async def find_active_system_invitations(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Find all active (non-used, non-expired) system invitations."""
        query = {
            "is_used": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        }
        cursor = self.system_invitations.find(query).skip(skip).limit(limit)
        return await cursor.to_list(limit)

    async def mark_system_invitation_used(self, invitation_id: str) -> None:
        """Mark system invitation as used."""
        await self.system_invitations.update_one({"_id": invitation_id}, {"$set": {"is_used": True}})

"""Repository for invitations."""

from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.invitation import SystemInvitation


class InvitationRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.system_invitations = db.system_invitations

    async def get_system_invitation_by_token(self, token: str) -> dict[str, Any] | None:
        return await self.system_invitations.find_one(
            {
                "token": token,
                "is_used": False,
                "expires_at": {"$gt": datetime.now(timezone.utc)},
            }
        )

    async def get_system_invitation_by_email(self, email: str) -> dict[str, Any] | None:
        return await self.system_invitations.find_one(
            {
                "email": email,
                "is_used": False,
                "expires_at": {"$gt": datetime.now(timezone.utc)},
            }
        )

    async def create_system_invitation(self, invitation: SystemInvitation) -> SystemInvitation:
        await self.system_invitations.insert_one(invitation.model_dump(by_alias=True))
        return invitation

    async def delete_system_invitation(self, invitation_id: str) -> bool:
        result = await self.system_invitations.delete_one({"_id": invitation_id})
        return result.deleted_count > 0

    async def find_active_system_invitations(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = {
            "is_used": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        }
        cursor = self.system_invitations.find(query).skip(skip).limit(limit)
        return await cursor.to_list(limit)

    async def mark_system_invitation_used(self, invitation_id: str) -> None:
        await self.system_invitations.update_one({"_id": invitation_id}, {"$set": {"is_used": True}})

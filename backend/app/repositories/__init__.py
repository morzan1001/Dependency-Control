"""
Repository Pattern for Database Access

Provides a clean abstraction layer over MongoDB collections,
centralizing database operations and reducing code duplication.
"""

from app.repositories.base import BaseRepository
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.broadcasts import BroadcastRepository
from app.repositories.callgraphs import CallgraphRepository
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.repositories.findings import FindingRepository
from app.repositories.invitations import InvitationRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.teams import TeamRepository
from app.repositories.users import UserRepository
from app.repositories.waivers import WaiverRepository
from app.repositories.webhooks import WebhookRepository

__all__ = [
    "BaseRepository",
    "AnalysisResultRepository",
    "BroadcastRepository",
    "CallgraphRepository",
    "DependencyRepository",
    "DependencyEnrichmentRepository",
    "FindingRepository",
    "InvitationRepository",
    "ProjectRepository",
    "ScanRepository",
    "SystemSettingsRepository",
    "TeamRepository",
    "UserRepository",
    "WaiverRepository",
    "WebhookRepository",
]

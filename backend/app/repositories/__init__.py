"""Repository pattern over MongoDB collections."""

from app.repositories.base import BaseRepository
from app.repositories.analysis_results import AnalysisResultRepository
from app.repositories.archive_metadata import ArchiveMetadataRepository
from app.repositories.broadcasts import BroadcastRepository
from app.repositories.callgraphs import CallgraphRepository
from app.repositories.crypto_asset import CryptoAssetRepository  # noqa: F401
from app.repositories.crypto_policy import CryptoPolicyRepository  # noqa: F401
from app.repositories.dependencies import DependencyRepository
from app.repositories.dependency_enrichments import DependencyEnrichmentRepository
from app.repositories.distributed_locks import DistributedLocksRepository
from app.repositories.findings import FindingRepository
from app.repositories.github_instances import GitHubInstanceRepository
from app.repositories.invitations import InvitationRepository
from app.repositories.projects import ProjectRepository
from app.repositories.scans import ScanRepository
from app.repositories.system_settings import SystemSettingsRepository
from app.repositories.teams import TeamRepository
from app.repositories.token_blacklist import TokenBlacklistRepository
from app.repositories.users import UserRepository
from app.repositories.waivers import WaiverRepository
from app.repositories.webhook_deliveries import WebhookDeliveriesRepository
from app.repositories.webhooks import WebhookRepository

__all__ = [
    "BaseRepository",
    "AnalysisResultRepository",
    "ArchiveMetadataRepository",
    "BroadcastRepository",
    "CallgraphRepository",
    "CryptoAssetRepository",
    "CryptoPolicyRepository",
    "DependencyRepository",
    "DependencyEnrichmentRepository",
    "DistributedLocksRepository",
    "FindingRepository",
    "GitHubInstanceRepository",
    "InvitationRepository",
    "ProjectRepository",
    "ScanRepository",
    "SystemSettingsRepository",
    "TeamRepository",
    "TokenBlacklistRepository",
    "UserRepository",
    "WaiverRepository",
    "WebhookDeliveriesRepository",
    "WebhookRepository",
]

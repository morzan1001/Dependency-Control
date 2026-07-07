"""Repository for GitHub instances."""

from app.models.github_instance import GitHubInstance
from app.repositories.vcs_instances import VcsInstanceRepository


class GitHubInstanceRepository(VcsInstanceRepository[GitHubInstance]):
    """Repository for GitHub instance database operations."""

    collection_name = "github_instances"
    model_class = GitHubInstance

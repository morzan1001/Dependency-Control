"""Repository for GitLab instances."""

from app.models.gitlab_instance import GitLabInstance
from app.repositories.vcs_instances import VcsInstanceRepository


class GitLabInstanceRepository(VcsInstanceRepository[GitLabInstance]):
    collection_name = "gitlab_instances"
    model_class = GitLabInstance
    project_link_field = "gitlab_instance_id"

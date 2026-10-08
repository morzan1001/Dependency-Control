"""Shared helper functions for API v1 endpoints."""

from app.api.v1.helpers.analytics import get_user_project_ids
from app.api.v1.helpers.callgraph import (
    detect_format,
    parse_generic_format,
    parse_madge_format,
)
from app.api.v1.helpers.findings import (
    aggregate_stats_by_category,
    get_category_for_type,
    get_category_type_filter,
)
from app.api.v1.helpers.ingest import process_findings_ingest
from app.api.v1.helpers.pagination import build_pagination_response
from app.api.v1.helpers.projects import (
    apply_system_settings_enforcement,
    authorize_waiver_read,
    build_user_project_query,
    check_project_access,
    generate_project_api_key,
    is_write_superuser,
    last_admin_guard,
    may_read_projects,
)
from app.api.v1.helpers.responses import (
    RESP_400,
    RESP_401,
    RESP_403,
    RESP_404,
    RESP_500,
    RESP_501,
    RESP_AUTH,
    RESP_AUTH_400,
    RESP_AUTH_400_404,
    RESP_AUTH_404,
)
from app.api.v1.helpers.sorting import (
    SORT_FIELDS,
    get_sort_field,
    parse_sort_direction,
)
from app.api.v1.helpers.system import get_available_channels
from app.api.v1.helpers.teams import (
    build_team_enrichment_pipeline,
    check_team_access,
    enrich_team_with_usernames,
    fetch_and_enrich_team,
    get_team_with_access,
    resolve_team_names,
    team_refs,
    visible_teams_filter,
)
from app.api.v1.helpers.users import (
    check_admin_or_self,
    ensure_can_manage_target,
    fetch_updated_user,
    get_user_or_404,
)
from app.api.v1.helpers.webhooks import (
    check_webhook_permission,
    get_webhook_or_404,
)

__all__ = [
    # Findings helpers
    # Response definitions
    "RESP_400",
    "RESP_401",
    "RESP_403",
    "RESP_404",
    "RESP_500",
    "RESP_501",
    "RESP_AUTH",
    "RESP_AUTH_400",
    "RESP_AUTH_400_404",
    "RESP_AUTH_404",
    # Sorting helpers
    "SORT_FIELDS",
    # Project helpers
    "aggregate_stats_by_category",
    "apply_system_settings_enforcement",
    "authorize_waiver_read",
    # Pagination helpers
    "build_pagination_response",
    # Team helpers
    "build_team_enrichment_pipeline",
    "build_user_project_query",
    # User helpers
    "check_admin_or_self",
    # Callgraph helpers
    "check_project_access",
    "check_team_access",
    # Webhook helpers
    "check_webhook_permission",
    "detect_format",
    "enrich_team_with_usernames",
    "ensure_can_manage_target",
    "fetch_and_enrich_team",
    "fetch_updated_user",
    "generate_project_api_key",
    # System helpers
    "get_available_channels",
    "get_category_for_type",
    "get_category_type_filter",
    "get_sort_field",
    "get_team_with_access",
    "get_user_or_404",
    "get_user_project_ids",
    "get_webhook_or_404",
    "is_write_superuser",
    "last_admin_guard",
    "may_read_projects",
    "parse_generic_format",
    "parse_madge_format",
    "parse_sort_direction",
    # Ingest helpers
    "process_findings_ingest",
    "resolve_team_names",
    "team_refs",
    "visible_teams_filter",
]

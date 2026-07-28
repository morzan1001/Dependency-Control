"""Shared helper functions for API v1 endpoints."""

from app.api.v1.helpers.analytics import (
    build_findings_severity_map,
    build_hotspot_priority_reasons,
    build_priority_reasons,
    calculate_days_known,
    calculate_days_until_due,
    calculate_impact_score,
    count_severities,
    extract_fix_versions,
    gather_cross_project_data,
    get_latest_scan_ids,
    get_projects_with_scans,
    get_user_project_ids,
    process_cve_enrichments,
    require_analytics_permission,
)
from app.api.v1.helpers.auth import (
    get_logo_path,
    send_password_reset_email,
    send_system_invitation_email,
    send_verification_email,
)
from app.api.v1.helpers.callgraph import (
    check_callgraph_access,
    detect_format,
    normalize_module_name,
    parse_generic_format,
    parse_madge_format,
    parse_pyan_format,
)
from app.api.v1.helpers.findings import (
    CATEGORY_TYPE_MAP,
    TYPE_CATEGORY_MAP,
    aggregate_stats_by_category,
    get_category_for_type,
    get_category_type_filter,
)
from app.api.v1.helpers.ingest import process_findings_ingest
from app.api.v1.helpers.integrations import (
    SlackOAuthError,
    exchange_slack_code_for_token,
    extract_slack_tokens,
)
from app.api.v1.helpers.pagination import build_pagination_response
from app.api.v1.helpers.projects import (
    apply_system_settings_enforcement,
    build_user_project_query,
    check_project_access,
    generate_project_api_key,
    is_write_superuser,
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
from app.api.v1.helpers.storage import (
    delete_gridfs_files,
    load_from_gridfs,
    resolve_sbom_refs,
)
from app.api.v1.helpers.system import get_available_channels
from app.api.v1.helpers.teams import (
    build_team_enrichment_pipeline,
    check_team_access,
    enrich_team_with_usernames,
    fetch_and_enrich_team,
    find_member_in_team,
    get_member_role,
    get_team_with_access,
)
from app.api.v1.helpers.users import (
    check_admin_or_self,
    fetch_updated_user,
    get_user_or_404,
    is_2fa_setup_mode,
)
from app.api.v1.helpers.webhooks import (
    check_team_webhook_create_permission,
    check_team_webhook_list_permission,
    check_webhook_create_permission,
    check_webhook_list_permission,
    check_webhook_permission,
    get_webhook_or_404,
)

__all__ = [
    # Findings helpers
    "CATEGORY_TYPE_MAP",
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
    "TYPE_CATEGORY_MAP",
    # Integration helpers
    "SlackOAuthError",
    "aggregate_stats_by_category",
    # Project helpers
    "apply_system_settings_enforcement",
    "build_findings_severity_map",
    "build_hotspot_priority_reasons",
    # Pagination helpers
    "build_pagination_response",
    "build_priority_reasons",
    # Team helpers
    "build_team_enrichment_pipeline",
    "build_user_project_query",
    "calculate_days_known",
    "calculate_days_until_due",
    "calculate_impact_score",
    # User helpers
    "check_admin_or_self",
    # Callgraph helpers
    "check_callgraph_access",
    "check_project_access",
    "check_team_access",
    # Webhook helpers
    "check_team_webhook_create_permission",
    "check_team_webhook_list_permission",
    "check_webhook_create_permission",
    "check_webhook_list_permission",
    "check_webhook_permission",
    "count_severities",
    # Storage helpers
    "delete_gridfs_files",
    "detect_format",
    "enrich_team_with_usernames",
    "exchange_slack_code_for_token",
    "extract_fix_versions",
    "extract_slack_tokens",
    "fetch_and_enrich_team",
    "fetch_updated_user",
    "find_member_in_team",
    "gather_cross_project_data",
    "generate_project_api_key",
    # System helpers
    "get_available_channels",
    "get_category_for_type",
    "get_category_type_filter",
    "get_latest_scan_ids",
    # Auth helpers
    "get_logo_path",
    "get_member_role",
    "get_projects_with_scans",
    "get_sort_field",
    "get_team_with_access",
    "get_user_or_404",
    "get_user_project_ids",
    "get_webhook_or_404",
    "is_2fa_setup_mode",
    "is_write_superuser",
    "load_from_gridfs",
    "normalize_module_name",
    "parse_generic_format",
    "parse_madge_format",
    "parse_pyan_format",
    "parse_sort_direction",
    "process_cve_enrichments",
    # Ingest helpers
    "process_findings_ingest",
    # Analytics helpers
    "require_analytics_permission",
    "resolve_sbom_refs",
    "send_password_reset_email",
    "send_system_invitation_email",
    "send_verification_email",
]

"""
API v1 Helper Functions

Shared helper functions extracted from endpoint modules for better
code organization and reusability.
"""

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
    check_webhook_create_permission,
    check_webhook_list_permission,
    check_webhook_permission,
    get_webhook_or_404,
)

__all__ = [
    # Auth helpers
    "get_logo_path",
    "send_verification_email",
    "send_password_reset_email",
    "send_system_invitation_email",
    # Analytics helpers
    "require_analytics_permission",
    "get_user_project_ids",
    "get_latest_scan_ids",
    "get_projects_with_scans",
    "calculate_days_until_due",
    "calculate_days_known",
    "extract_fix_versions",
    "process_cve_enrichments",
    "calculate_impact_score",
    "build_priority_reasons",
    "build_hotspot_priority_reasons",
    "build_findings_severity_map",
    "gather_cross_project_data",
    "count_severities",
    # Callgraph helpers
    "check_callgraph_access",
    "normalize_module_name",
    "parse_madge_format",
    "parse_pyan_format",
    "parse_generic_format",
    "detect_format",
    # Findings helpers
    "CATEGORY_TYPE_MAP",
    "TYPE_CATEGORY_MAP",
    "get_category_type_filter",
    "get_category_for_type",
    "aggregate_stats_by_category",
    # Ingest helpers
    "process_findings_ingest",
    # Integration helpers
    "SlackOAuthError",
    "exchange_slack_code_for_token",
    "extract_slack_tokens",
    # Pagination helpers
    "build_pagination_response",
    # Project helpers
    "apply_system_settings_enforcement",
    "build_user_project_query",
    "check_project_access",
    "generate_project_api_key",
    # Sorting helpers
    "SORT_FIELDS",
    "get_sort_field",
    "parse_sort_direction",
    # Storage helpers
    "delete_gridfs_files",
    "load_from_gridfs",
    "resolve_sbom_refs",
    # System helpers
    "get_available_channels",
    # Team helpers
    "build_team_enrichment_pipeline",
    "check_team_access",
    "enrich_team_with_usernames",
    "fetch_and_enrich_team",
    "find_member_in_team",
    "get_member_role",
    "get_team_with_access",
    # User helpers
    "check_admin_or_self",
    "fetch_updated_user",
    "get_user_or_404",
    "is_2fa_setup_mode",
    # Webhook helpers
    "check_webhook_create_permission",
    "check_webhook_list_permission",
    "check_webhook_permission",
    "get_webhook_or_404",
]

"""Chat tool definitions and execution dispatch.

External collaborators are re-exported here so ``unittest.mock.patch`` can
target ``app.services.chat.tools.<NAME>``; crypto tool functions resolve them
lazily through this package's namespace.
"""

import logging

# These re-exports must be defined BEFORE the crypto_tools import so the
# patched references stay reachable via the package namespace at call time.
from app.repositories.compliance_report import ComplianceReportRepository
from app.repositories.policy_audit_entry import PolicyAuditRepository
from app.schemas.compliance import ReportFramework
from app.services.analytics.scopes import ResolvedScope, ScopeResolver
from app.services.compliance.engine import ComplianceReportEngine
from app.services.compliance.frameworks import FRAMEWORK_REGISTRY
from app.services.pqc_migration.generator import PQCMigrationPlanGenerator

from ._helpers import (
    KEV_EQUIVALENT_MATURITY,
    MAX_TOOL_LIMIT,
    MAX_TOOL_RESULT_BYTES,
    _breaking_risk,
    _clamp_limit,
    _clip_value,
    _compare_versions,
    _inject_urls,
    _parse_major,
    _serialize_doc,
    _serialize_finding_for_llm,
    _summary_severity_bucket,
    _truncate_if_too_large,
)
from .crypto_tools import (
    generate_pqc_migration_plan,
    get_crypto_asset_details,
    get_crypto_hotspots,
    get_crypto_summary,
    get_crypto_trends,
    get_framework_evaluation_summary,
    get_project_crypto_policy,
    get_scan_delta,
    list_compliance_reports,
    list_crypto_assets,
    list_policy_audit_entries,
    suggest_crypto_policy_override,
)
from .definitions import TOOL_DEFINITIONS, TOOL_PERMISSIONS, get_tool_definitions
from .registry import ChatToolRegistry

logger = logging.getLogger(__name__)

__all__ = [
    "KEV_EQUIVALENT_MATURITY",
    "MAX_TOOL_LIMIT",
    "MAX_TOOL_RESULT_BYTES",
    "ComplianceReportEngine",
    "ComplianceReportRepository",
    "FRAMEWORK_REGISTRY",
    "PQCMigrationPlanGenerator",
    "PolicyAuditRepository",
    "ReportFramework",
    "ResolvedScope",
    "ScopeResolver",
    "_breaking_risk",
    "_clamp_limit",
    "_clip_value",
    "_compare_versions",
    "_inject_urls",
    "_parse_major",
    "_serialize_doc",
    "_serialize_finding_for_llm",
    "_summary_severity_bucket",
    "_truncate_if_too_large",
    "TOOL_DEFINITIONS",
    "TOOL_PERMISSIONS",
    "get_tool_definitions",
    "ChatToolRegistry",
    "generate_pqc_migration_plan",
    "get_crypto_asset_details",
    "get_crypto_hotspots",
    "get_crypto_summary",
    "get_crypto_trends",
    "get_framework_evaluation_summary",
    "get_project_crypto_policy",
    "get_scan_delta",
    "list_compliance_reports",
    "list_crypto_assets",
    "list_policy_audit_entries",
    "suggest_crypto_policy_override",
]

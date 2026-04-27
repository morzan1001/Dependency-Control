"""Chat tool definitions and execution dispatch.

This package replaces the previous monolithic ``tools.py`` module. All public
symbols that used to live there are re-exported here so existing import paths
(``from app.services.chat.tools import ChatToolRegistry``, ...) keep working
without changes.

Submodules:
  * ``_helpers``      — pure-Python utilities (clamp, serialize, truncate, ...)
  * ``definitions``   — TOOL_DEFINITIONS / TOOL_PERMISSIONS / get_tool_definitions
  * ``crypto_tools``  — standalone async tool functions for crypto / compliance
  * ``registry``      — ChatToolRegistry dispatcher class

External symbols (``ScopeResolver``, ``PQCMigrationPlanGenerator``,
``ComplianceReportRepository``, ``PolicyAuditRepository``,
``ComplianceReportEngine``, ``FRAMEWORK_REGISTRY``, ``ReportFramework``,
``ResolvedScope``) are imported here so ``unittest.mock.patch`` can target
``app.services.chat.tools.<NAME>`` exactly the way the test suite did before
the split — the crypto tool functions resolve them lazily through this
package's namespace.
"""

import logging

# Re-exported third-party / sibling imports that tests patch on this module.
# Must be defined BEFORE the crypto_tools import so the patched references
# stay reachable via the package namespace at call time.
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
    # Constants
    "KEV_EQUIVALENT_MATURITY",
    "MAX_TOOL_LIMIT",
    "MAX_TOOL_RESULT_BYTES",
    # Re-exported collaborators (kept here so tests can patch them)
    "ComplianceReportEngine",
    "ComplianceReportRepository",
    "FRAMEWORK_REGISTRY",
    "PQCMigrationPlanGenerator",
    "PolicyAuditRepository",
    "ReportFramework",
    "ResolvedScope",
    "ScopeResolver",
    # Helpers (private but a few callers import them directly)
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
    # Static metadata + dispatcher
    "TOOL_DEFINITIONS",
    "TOOL_PERMISSIONS",
    "get_tool_definitions",
    "ChatToolRegistry",
    # Standalone async tool functions
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

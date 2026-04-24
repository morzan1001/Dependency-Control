"""Framework-evaluation modules.

Each framework exports a class implementing `ComplianceFramework`. The
framework key maps to the class via `FRAMEWORK_REGISTRY`, populated at the
bottom of this file after all imports resolve.
"""

from app.schemas.compliance import ReportFramework
from app.services.compliance.frameworks.base import (
    ComplianceFramework,
    EvaluationInput,
    default_evaluator,
)
from app.services.compliance.frameworks.nist_sp_800_131a import NistSp800_131aFramework
from app.services.compliance.frameworks.bsi_tr_02102 import BsiTr02102Framework
from app.services.compliance.frameworks.cnsa_2_0 import Cnsa20Framework
from app.services.compliance.frameworks.fips_140_3 import Fips1403Framework
from app.services.compliance.frameworks.iso_19790 import Iso19790Framework
from app.services.compliance.frameworks.pqc_migration_plan import PQCMigrationPlanFramework
from app.services.compliance.frameworks.license_audit import LicenseAuditFramework
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework

FRAMEWORK_REGISTRY: "dict[ReportFramework, ComplianceFramework]" = {
    # Crypto / CBOM frameworks
    ReportFramework.NIST_SP_800_131A: NistSp800_131aFramework(),
    ReportFramework.BSI_TR_02102: BsiTr02102Framework(),
    ReportFramework.CNSA_2_0: Cnsa20Framework(),
    ReportFramework.FIPS_140_3: Fips1403Framework(),
    ReportFramework.ISO_19790: Iso19790Framework(),
    ReportFramework.PQC_MIGRATION_PLAN: PQCMigrationPlanFramework(),
    # SBOM frameworks
    ReportFramework.LICENSE_AUDIT: LicenseAuditFramework(),
    ReportFramework.CVE_REMEDIATION_SLA: CveRemediationSlaFramework(),
}

__all__ = [
    "FRAMEWORK_REGISTRY",
    "ComplianceFramework",
    "EvaluationInput",
    "default_evaluator",
]

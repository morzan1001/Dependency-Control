"""Framework-evaluation modules, keyed into FRAMEWORK_REGISTRY."""

from app.schemas.compliance import ReportFramework
from app.services.compliance.frameworks.base import ComplianceFramework, SeedFramework
from app.services.compliance.frameworks.cve_remediation_sla import CveRemediationSlaFramework
from app.services.compliance.frameworks.fips_140_3 import Fips1403Framework
from app.services.compliance.frameworks.iso_19790 import Iso19790Framework
from app.services.compliance.frameworks.license_audit import LicenseAuditFramework
from app.services.compliance.frameworks.pqc_migration_plan import PQCMigrationPlanFramework

FRAMEWORK_REGISTRY: "dict[ReportFramework, ComplianceFramework]" = {
    ReportFramework.NIST_SP_800_131A: SeedFramework(
        key=ReportFramework.NIST_SP_800_131A,
        name="NIST SP 800-131A (Transitioning Cryptographic Algorithms and Key Lengths)",
        version="Rev.3",
        seed_file="nist_sp_800_131a.yaml",
        control_id_prefix="NIST-131A",
    ),
    ReportFramework.BSI_TR_02102: SeedFramework(
        key=ReportFramework.BSI_TR_02102,
        name="BSI TR-02102-1 (Cryptographic Mechanisms: Recommendations and Key Lengths)",
        version="2024",
        seed_file="bsi_tr_02102.yaml",
        control_id_prefix="BSI-02102",
    ),
    ReportFramework.CNSA_2_0: SeedFramework(
        key=ReportFramework.CNSA_2_0,
        name="CNSA 2.0 (Commercial National Security Algorithm Suite)",
        version="2022",
        seed_file="cnsa_2_0.yaml",
        control_id_prefix="CNSA20",
    ),
    ReportFramework.FIPS_140_3: Fips1403Framework(),
    ReportFramework.ISO_19790: Iso19790Framework(),
    ReportFramework.PQC_MIGRATION_PLAN: PQCMigrationPlanFramework(),
    ReportFramework.LICENSE_AUDIT: LicenseAuditFramework(),
    ReportFramework.CVE_REMEDIATION_SLA: CveRemediationSlaFramework(),
}

__all__ = ["FRAMEWORK_REGISTRY"]

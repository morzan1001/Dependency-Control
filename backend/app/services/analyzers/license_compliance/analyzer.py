"""License compliance analyzer.

Top-level orchestration that walks SBOM components, dispatches each one to
the per-license evaluator, and aggregates findings + summary stats. Heavy
lifting (constants, normalization, evaluation, cross-component compatibility)
lives in sibling modules; this class delegates to them and exposes thin
``self``-bound wrappers so existing test imports keep working.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LibraryUsage,
    LicenseCategory,
    LicenseInfo,
    LicensePolicy,
)

from ..base import Analyzer
from . import compatibility, evaluator, normalizer
from .constants import (
    CATEGORY_STAT_KEY,
    LICENSE_DATABASE,
    SEVERITY_RANK,
)


class LicenseAnalyzer(Analyzer):
    name = "license_compliance"

    # Re-exposed for backward compatibility with tests / external callers
    LICENSE_DATABASE: Dict[str, LicenseInfo] = LICENSE_DATABASE
    _CATEGORY_STAT_KEY: Dict[LicenseCategory, str] = CATEGORY_STAT_KEY

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Analyze SBOM components for license compliance issues.

        Settings can include:
        - allow_strong_copyleft: bool - Allow GPL-style licenses (default: False)
        - allow_network_copyleft: bool - Allow AGPL/SSPL (default: False)
        - ignore_dev_dependencies: bool - Skip devDependencies (default: True)
        - ignore_transitive: bool - Only check direct deps (default: False)
        """
        settings = settings or {}
        ignore_dev = settings.get("ignore_dev_dependencies", True)
        ignore_transitive = settings.get("ignore_transitive", False)

        # Build LicensePolicy from settings.
        # Precedence: settings (already merged from analyzer_settings.license_compliance by engine)
        # falls back to legacy top-level "license_policy" key for backward compat.
        policy_raw = settings.get("license_policy", {})
        if not policy_raw and any(k in settings for k in ("distribution_model", "deployment_model", "library_usage")):
            # New-style: settings come directly from analyzer_settings["license_compliance"]
            policy_raw = settings
        policy = LicensePolicy(
            distribution_model=DistributionModel(policy_raw.get("distribution_model", "distributed")),
            deployment_model=DeploymentModel(policy_raw.get("deployment_model", "network_facing")),
            library_usage=LibraryUsage(policy_raw.get("library_usage", "mixed")),
            allow_strong_copyleft=policy_raw.get("allow_strong_copyleft", settings.get("allow_strong_copyleft", False)),
            allow_network_copyleft=policy_raw.get(
                "allow_network_copyleft", settings.get("allow_network_copyleft", False)
            ),
        )

        components = self._get_components(sbom, parsed_components)
        issues: List[Dict[str, Any]] = []

        stats = {
            "total_components": len(components),
            "permissive": 0,
            "weak_copyleft": 0,
            "strong_copyleft": 0,
            "network_copyleft": 0,
            "proprietary": 0,
            "unknown": 0,
            "skipped": 0,
        }

        for component in components:
            self._analyze_component(
                component,
                stats,
                issues,
                ignore_dev=ignore_dev,
                ignore_transitive=ignore_transitive,
                policy=policy,
            )

        # Cross-dependency license compatibility check
        compatibility_issues = compatibility.check_license_compatibility(components, ignore_dev)
        issues.extend(compatibility_issues)

        return {"license_issues": issues, "summary": stats}

    def _analyze_component(
        self,
        component: Dict[str, Any],
        stats: Dict[str, int],
        issues: List[Dict[str, Any]],
        *,
        ignore_dev: bool,
        ignore_transitive: bool,
        policy: LicensePolicy,
    ) -> None:
        """Analyze a single component for license compliance."""
        comp_scope = (component.get("scope") or "").lower()

        if ignore_dev and comp_scope in ("dev", "development", "test", "optional"):
            stats["skipped"] += 1
            return

        is_transitive = not component.get("properties", {}).get("direct", True)
        if ignore_transitive and is_transitive:
            stats["skipped"] += 1
            return

        comp_name = component.get("name", "unknown")
        comp_version = component.get("version", "unknown")
        comp_purl = component.get("purl", "")

        # Check for SPDX OR expressions — use expression-aware evaluation
        spdx_expr = normalizer.has_spdx_expression(component)
        if spdx_expr:
            or_groups = normalizer.parse_spdx_expression(spdx_expr)
            # Track stats for the best choice
            self._track_expression_stats(or_groups, stats)
            issue = self._evaluate_expression(
                comp_name,
                comp_version,
                comp_purl,
                or_groups,
                policy,
            )
            if issue:
                issue["spdx_expression"] = spdx_expr
                evaluator.apply_transitive_adjustment(issue, is_transitive)
                if evaluator.should_include_finding(issue, is_transitive):
                    issues.append(issue)
            return

        # Standard per-license evaluation (no OR expression)
        licenses = normalizer.extract_licenses(component)
        if not licenses:
            stats["unknown"] += 1
            return

        for lic_id, lic_url in licenses:
            normalized = normalizer.normalize_license(lic_id)
            license_info = LICENSE_DATABASE.get(normalized)

            if not license_info:
                stats["unknown"] += 1
                continue

            stat_key = CATEGORY_STAT_KEY.get(license_info.category)
            if stat_key:
                stats[stat_key] += 1

            issue = evaluator.evaluate_license(
                component=comp_name,
                version=comp_version,
                license_info=license_info,
                lic_url=lic_url,
                purl=comp_purl,
                policy=policy,
            )
            if issue:
                evaluator.apply_transitive_adjustment(issue, is_transitive)
                if evaluator.should_include_finding(issue, is_transitive):
                    issues.append(issue)

    def _track_expression_stats(self, or_groups: List[List[str]], stats: Dict[str, int]) -> None:
        """Track license category stats for the best OR alternative."""
        # Find the least restrictive OR group to track
        best_rank = 999
        best_licenses: List[str] = []
        for group in or_groups:
            worst_rank = 0
            for lic_id in group:
                normalized = normalizer.normalize_license(lic_id)
                info = LICENSE_DATABASE.get(normalized)
                if info:
                    cat_rank = {
                        LicenseCategory.PERMISSIVE: 0,
                        LicenseCategory.PUBLIC_DOMAIN: 0,
                        LicenseCategory.WEAK_COPYLEFT: 1,
                        LicenseCategory.STRONG_COPYLEFT: 2,
                        LicenseCategory.NETWORK_COPYLEFT: 3,
                        LicenseCategory.PROPRIETARY: 4,
                    }.get(info.category, 5)
                    worst_rank = max(worst_rank, cat_rank)
            if worst_rank < best_rank:
                best_rank = worst_rank
                best_licenses = group

        for lic_id in best_licenses:
            normalized = normalizer.normalize_license(lic_id)
            info = LICENSE_DATABASE.get(normalized)
            if info:
                stat_key = CATEGORY_STAT_KEY.get(info.category)
                if stat_key:
                    stats[stat_key] += 1

    def _evaluate_expression(
        self,
        comp_name: str,
        comp_version: str,
        comp_purl: str,
        or_groups: List[List[str]],
        policy: LicensePolicy,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate an SPDX expression by choosing the least restrictive OR-alternative.

        For OR: pick the alternative with the lowest severity (user can choose).
        For AND within an alternative: pick the highest severity (all apply).
        """
        best_issue: Optional[Dict[str, Any]] = None
        best_severity_rank = 999

        for and_group in or_groups:
            # Evaluate all AND-connected licenses — worst (highest severity) wins
            worst_issue: Optional[Dict[str, Any]] = None
            worst_rank = -1

            for lic_id in and_group:
                normalized = normalizer.normalize_license(lic_id)
                license_info = LICENSE_DATABASE.get(normalized)
                if not license_info:
                    continue

                issue = evaluator.evaluate_license(
                    component=comp_name,
                    version=comp_version,
                    license_info=license_info,
                    lic_url=None,
                    purl=comp_purl,
                    policy=policy,
                )
                rank = SEVERITY_RANK.get(issue["severity"] if issue else None, 0)
                if rank > worst_rank:
                    worst_rank = rank
                    worst_issue = issue

            # For OR: pick the least restrictive alternative
            if worst_rank < best_severity_rank:
                best_severity_rank = worst_rank
                best_issue = worst_issue

        return best_issue

    # ------------------------------------------------------------------
    # Backward-compatibility wrappers (used by external tests)
    # ------------------------------------------------------------------

    def _normalize_license(self, lic_id: str) -> str:
        """Normalize a license identifier to SPDX format (delegates to ``normalizer``)."""
        return normalizer.normalize_license(lic_id)

    def _extract_licenses(self, component: Dict[str, Any]) -> List[Tuple[str, Optional[str]]]:
        """Extract license identifiers and URLs from a component (delegates to ``normalizer``)."""
        return normalizer.extract_licenses(component)

    def _evaluate_license(
        self,
        component: str,
        version: str,
        license_info: LicenseInfo,
        lic_url: Optional[str],
        purl: str,
        policy: LicensePolicy,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a license and return an issue if problematic (delegates to ``evaluator``)."""
        return evaluator.evaluate_license(
            component=component,
            version=version,
            license_info=license_info,
            lic_url=lic_url,
            purl=purl,
            policy=policy,
        )

    def _has_spdx_expression(self, component: Dict[str, Any]) -> Optional[str]:
        """Return the SPDX OR-expression for a component (delegates to ``normalizer``)."""
        return normalizer.has_spdx_expression(component)

    def _parse_spdx_expression(self, expr: str) -> List[List[str]]:
        """Parse an SPDX expression into OR-groups of AND-connected licenses."""
        return normalizer.parse_spdx_expression(expr)

    @staticmethod
    def _apply_transitive_adjustment(issue: Dict[str, Any], is_transitive: bool) -> None:
        """Reduce severity for transitive dependencies (delegates to ``evaluator``)."""
        evaluator.apply_transitive_adjustment(issue, is_transitive)

    @staticmethod
    def _should_include_finding(issue: Dict[str, Any], is_transitive: bool) -> bool:
        """Decide whether a finding belongs in the result set (delegates to ``evaluator``)."""
        return evaluator.should_include_finding(issue, is_transitive)

    def _check_license_compatibility(
        self,
        components: List[Dict[str, Any]],
        ignore_dev: bool,
    ) -> List[Dict[str, Any]]:
        """Cross-component license-pair conflict check (delegates to ``compatibility``)."""
        return compatibility.check_license_compatibility(components, ignore_dev)

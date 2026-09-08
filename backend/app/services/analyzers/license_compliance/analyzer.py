"""License compliance analyzer that walks SBOM components and aggregates findings."""

from __future__ import annotations

from typing import Any

from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LibraryUsage,
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

    LICENSE_DATABASE: dict[str, LicenseInfo] = LICENSE_DATABASE

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Analyze SBOM components for license compliance issues."""
        settings = settings or {}
        ignore_dev = settings.get("ignore_dev_dependencies", True)
        ignore_transitive = settings.get("ignore_transitive", False)

        # Nested license_policy takes precedence over top-level policy keys.
        policy_raw = settings.get("license_policy", {})
        if not policy_raw and any(k in settings for k in ("distribution_model", "deployment_model", "library_usage")):
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
        issues: list[dict[str, Any]] = []
        component_licenses: list[dict[str, Any]] = []

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
                component_licenses,
                ignore_dev=ignore_dev,
                ignore_transitive=ignore_transitive,
                policy=policy,
            )

        compatibility_issues = compatibility.check_license_compatibility(components, ignore_dev)
        issues.extend(compatibility_issues)

        return {"license_issues": issues, "summary": stats, "component_licenses": component_licenses}

    def _analyze_component(
        self,
        component: dict[str, Any],
        stats: dict[str, int],
        issues: list[dict[str, Any]],
        component_licenses: list[dict[str, Any]],
        *,
        ignore_dev: bool,
        ignore_transitive: bool,
        policy: LicensePolicy,
    ) -> None:
        comp_scope = (component.get("scope") or "").lower()

        if ignore_dev and comp_scope in ("dev", "development", "test", "optional"):
            stats["skipped"] += 1
            return

        # Default to direct when unknown so unknown deps are never skipped or downgraded.
        is_transitive = not component.get("direct", True)
        if ignore_transitive and is_transitive:
            stats["skipped"] += 1
            return

        comp_name = component.get("name", "unknown")
        comp_version = component.get("version", "unknown")
        comp_purl = component.get("purl", "")

        spdx_expr = normalizer.has_spdx_expression(component)
        if spdx_expr:
            self._analyze_or_expression(
                comp_name,
                comp_version,
                comp_purl,
                spdx_expr,
                stats,
                issues,
                component_licenses,
                is_transitive=is_transitive,
                policy=policy,
            )
            return

        licenses = normalizer.extract_licenses(component)
        if not licenses:
            stats["unknown"] += 1
            issues.append(evaluator.create_undeterminable_issue(comp_name, comp_version, comp_purl, []))
            return

        # AND/WITH/comma composites reach this path member-by-member; keep the raw
        # expression on each issue so the declared license survives enrichment.
        raw_expression = normalizer.composite_license_expression(component)

        unrecognized: list[str] = []
        for lic_id, lic_url in licenses:
            normalized = normalizer.normalize_license(lic_id)
            license_info = LICENSE_DATABASE.get(normalized)

            if not license_info:
                stats["unknown"] += 1
                unrecognized.append(normalized)
                continue

            stat_key = CATEGORY_STAT_KEY.get(license_info.category)
            if stat_key:
                stats[stat_key] += 1

            component_licenses.append(
                self._classification_entry(comp_name, comp_version, comp_purl, normalized, license_info, raw_expression)
            )

            issue = evaluator.evaluate_license(
                component=comp_name,
                version=comp_version,
                license_info=license_info,
                lic_url=lic_url,
                purl=comp_purl,
                policy=policy,
            )
            if issue:
                if raw_expression:
                    issue["spdx_expression"] = raw_expression
                evaluator.apply_transitive_adjustment(issue, is_transitive)
                if evaluator.should_include_finding(issue, is_transitive):
                    issues.append(issue)

        if unrecognized:
            # Neither adjusted nor filtered by transitivity: the audit control reads presence, so
            # dropping the transitive ones would let it pass over components it cannot audit.
            issues.append(evaluator.create_undeterminable_issue(comp_name, comp_version, comp_purl, unrecognized))

    @staticmethod
    def _classification_entry(
        comp_name: str,
        comp_version: str,
        comp_purl: str,
        spdx_id: str,
        license_info: LicenseInfo,
        spdx_expression: str | None,
    ) -> dict[str, Any]:
        """Classification of one component license, emitted regardless of policy verdict."""
        entry: dict[str, Any] = {
            "component": comp_name,
            "version": comp_version,
            "purl": comp_purl,
            "license": spdx_id,
            "category": license_info.category.value,
            "obligations": license_info.obligations,
            "risks": license_info.risks,
            "explanation": license_info.description,
        }
        if spdx_expression:
            entry["spdx_expression"] = spdx_expression
        return entry

    def _analyze_or_expression(
        self,
        comp_name: str,
        comp_version: str,
        comp_purl: str,
        spdx_expr: str,
        stats: dict[str, int],
        issues: list[dict[str, Any]],
        component_licenses: list[dict[str, Any]],
        *,
        is_transitive: bool,
        policy: LicensePolicy,
    ) -> None:
        """Resolve an OR-expression to the alternative a consumer would take, or report it undeterminable."""
        or_groups = normalizer.parse_spdx_expression(spdx_expr)
        readable_groups, unreadable = compatibility.partition_or_groups(or_groups)
        selected, issue = self._select_or_alternative(comp_name, comp_version, comp_purl, readable_groups, policy)

        if selected is None or (unreadable and not evaluator.is_acceptable_under_policy(issue)):
            # No alternative is both readable and acceptable, so the expression settles nothing:
            # an acceptable licence may sit behind the identifier we do not recognise.
            stats["unknown"] += 1
            rejected = [normalizer.normalize_license(lic_id) for group in readable_groups for lic_id in group]
            issues.append(
                evaluator.create_undeterminable_issue(comp_name, comp_version, comp_purl, unreadable, rejected)
            )
            return

        for lic_id in selected:
            normalized = normalizer.normalize_license(lic_id)
            info = LICENSE_DATABASE[normalized]
            stat_key = CATEGORY_STAT_KEY.get(info.category)
            if stat_key:
                stats[stat_key] += 1
            component_licenses.append(
                self._classification_entry(comp_name, comp_version, comp_purl, normalized, info, spdx_expr)
            )

        if issue:
            issue["spdx_expression"] = spdx_expr
            evaluator.apply_transitive_adjustment(issue, is_transitive)
            if evaluator.should_include_finding(issue, is_transitive):
                issues.append(issue)

    @staticmethod
    def _select_or_alternative(
        comp_name: str,
        comp_version: str,
        comp_purl: str,
        readable_groups: list[list[str]],
        policy: LicensePolicy,
    ) -> tuple[list[str] | None, dict[str, Any] | None]:
        """Choose the OR-alternative a consumer would take: lowest-severity group, each ranked by its worst
        AND-member. Returns the chosen group and its verdict, or (None, None) when nothing is readable."""
        candidates: list[tuple[int, list[str], dict[str, Any] | None]] = []

        for and_group in readable_groups:
            evaluated: list[tuple[int, dict[str, Any] | None]] = []
            for lic_id in and_group:
                issue = evaluator.evaluate_license(
                    component=comp_name,
                    version=comp_version,
                    license_info=LICENSE_DATABASE[normalizer.normalize_license(lic_id)],
                    lic_url=None,
                    purl=comp_purl,
                    policy=policy,
                )
                evaluated.append((SEVERITY_RANK[issue["severity"] if issue else None], issue))
            worst_rank, worst_issue = max(evaluated, key=lambda pair: pair[0])
            candidates.append((worst_rank, and_group, worst_issue))

        if not candidates:
            return None, None
        _, best_group, best_issue = min(candidates, key=lambda candidate: candidate[0])
        return best_group, best_issue

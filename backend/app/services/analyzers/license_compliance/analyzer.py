"""License compliance analyzer that walks SBOM components and aggregates findings."""

from __future__ import annotations

from typing import Any

from app.core.constants import NON_RUNTIME_SCOPES, get_severity_value
from app.models.license import LicenseInfo
from app.schemas.project import LicensePolicySchema, license_policy_from_settings

from ..base import Analyzer
from . import compatibility, evaluator, normalizer
from .constants import (
    CATEGORY_STAT_KEY,
    LICENSE_DATABASE,
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
        policy = license_policy_from_settings(settings)

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
            self._analyze_component(component, stats, issues, component_licenses, policy=policy)

        compatibility_issues = compatibility.check_license_compatibility(components, policy.ignore_dev_dependencies)
        issues.extend(compatibility_issues)

        return {"license_issues": issues, "summary": stats, "component_licenses": component_licenses}

    def _analyze_component(
        self,
        component: dict[str, Any],
        stats: dict[str, int],
        issues: list[dict[str, Any]],
        component_licenses: list[dict[str, Any]],
        *,
        policy: LicensePolicySchema,
    ) -> None:
        # The distro descriptor is kept for EOL detection; it is not a licensed dependency.
        if component.get("type") == "operating-system":
            stats["skipped"] += 1
            return

        if policy.ignore_dev_dependencies and (component.get("scope") or "").lower() in NON_RUNTIME_SCOPES:
            stats["skipped"] += 1
            return

        # Default to direct when unknown so unknown deps are never skipped or downgraded.
        is_transitive = not component.get("direct", True)
        if policy.ignore_transitive and is_transitive:
            stats["skipped"] += 1
            return

        declared = component.get("license") or ""
        or_groups = normalizer.parse_license_expression(declared)
        if len(or_groups) > 1:
            self._analyze_or_expression(
                component,
                declared,
                or_groups,
                stats,
                issues,
                component_licenses,
                is_transitive=is_transitive,
                policy=policy,
            )
            return

        members = or_groups[0] if or_groups else []
        if not members:
            stats["unknown"] += 1
            issues.append(evaluator.create_undeterminable_issue(component, []))
            return

        # Keep the declared composite on each issue so the full license survives enrichment.
        raw_expression = declared if len(members) > 1 or " WITH " in members[0] else None
        lic_url = component.get("license_url")

        unrecognized: list[str] = []
        for member in members:
            normalized = member.partition(" WITH ")[0]
            if normalized not in LICENSE_DATABASE and len(members) == 1:
                # A lone licence's URL is its own; with several, the one stored URL may belong to another.
                normalized = normalizer.extract_license_from_url(lic_url) or normalized
            license_info = LICENSE_DATABASE.get(normalized)

            if not license_info:
                stats["unknown"] += 1
                unrecognized.append(normalized)
                continue

            stat_key = CATEGORY_STAT_KEY.get(license_info.category)
            if stat_key:
                stats[stat_key] += 1

            component_licenses.append(self._classification_entry(component, normalized, license_info, raw_expression))

            issue = evaluator.evaluate_license(component, license_info, policy, lic_url)
            if issue:
                if raw_expression:
                    issue["spdx_expression"] = raw_expression
                evaluator.apply_transitive_adjustment(issue, is_transitive)
                if evaluator.should_include_finding(issue, is_transitive):
                    issues.append(issue)

        if unrecognized:
            # Neither adjusted nor filtered by transitivity: the audit control reads presence, so
            # dropping the transitive ones would let it pass over components it cannot audit.
            issues.append(evaluator.create_undeterminable_issue(component, unrecognized))

    @staticmethod
    def _classification_entry(
        component: dict[str, Any],
        spdx_id: str,
        license_info: LicenseInfo,
        spdx_expression: str | None,
    ) -> dict[str, Any]:
        """Classification of one component license, emitted regardless of policy verdict."""
        entry: dict[str, Any] = {
            "component": component.get("name", "unknown"),
            "version": component.get("version", "unknown"),
            "purl": component.get("purl", ""),
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
        component: dict[str, Any],
        spdx_expr: str,
        or_groups: list[list[str]],
        stats: dict[str, int],
        issues: list[dict[str, Any]],
        component_licenses: list[dict[str, Any]],
        *,
        is_transitive: bool,
        policy: LicensePolicySchema,
    ) -> None:
        """Resolve an OR-expression to the alternative a consumer would take, or report it undeterminable."""
        readable_groups, unreadable = compatibility.partition_or_groups(or_groups)
        selected, issue = self._select_or_alternative(component, readable_groups, policy)

        if selected is None or (unreadable and not evaluator.is_acceptable_under_policy(issue)):
            # No alternative is both readable and acceptable, so the expression settles nothing:
            # an acceptable licence may sit behind the identifier we do not recognise.
            stats["unknown"] += 1
            rejected = list(dict.fromkeys(lic_id for group in readable_groups for lic_id in group))
            issues.append(evaluator.create_undeterminable_issue(component, unreadable, rejected))
            return

        for lic_id in selected:
            info = LICENSE_DATABASE[lic_id]
            stat_key = CATEGORY_STAT_KEY.get(info.category)
            if stat_key:
                stats[stat_key] += 1
            component_licenses.append(self._classification_entry(component, lic_id, info, spdx_expr))

        if issue:
            issue["spdx_expression"] = spdx_expr
            evaluator.apply_transitive_adjustment(issue, is_transitive)
            if evaluator.should_include_finding(issue, is_transitive):
                issues.append(issue)

    @staticmethod
    def _select_or_alternative(
        component: dict[str, Any],
        readable_groups: list[list[str]],
        policy: LicensePolicySchema,
    ) -> tuple[list[str] | None, dict[str, Any] | None]:
        """Choose the OR-alternative a consumer would take: lowest-severity group, each ranked by its worst
        AND-member. Returns the chosen group and its verdict, or (None, None) when nothing is readable."""
        candidates: list[tuple[int, list[str], dict[str, Any] | None]] = []

        for and_group in readable_groups:
            evaluated: list[tuple[int, dict[str, Any] | None]] = []
            for lic_id in and_group:
                issue = evaluator.evaluate_license(component, LICENSE_DATABASE[lic_id], policy)
                # No issue ranks below every severity, INFO included.
                evaluated.append((get_severity_value(issue["severity"]) if issue else -1, issue))
            worst_rank, worst_issue = max(evaluated, key=lambda pair: pair[0])
            candidates.append((worst_rank, and_group, worst_issue))

        if not candidates:
            return None, None
        _, best_group, best_issue = min(candidates, key=lambda candidate: candidate[0])
        return best_group, best_issue

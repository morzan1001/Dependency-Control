"""License compliance analyzer that walks SBOM components and aggregates findings."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from app.core.constants import NON_RUNTIME_SCOPES, get_severity_value
from app.models.license import CATEGORY_RESTRICTIVENESS, LicenseCategory, LicenseInfo
from app.schemas.project import LicensePolicySchema, license_policy_from_settings

from ..base import Analyzer
from . import compatibility, evaluator, normalizer
from .constants import (
    CATEGORY_STAT_KEY,
    INCLUDE_LICENSE_TEXT,
    LICENSE_DATABASE,
    SHARE_SOURCE_OF_MODIFICATIONS,
)


def classify_license(member: str, license_id: str | None = None) -> LicenseInfo | None:
    """The catalogue entry for an expression member, its linking exception applied; license_id overrides its id."""
    license_info = LICENSE_DATABASE.get(license_id or member.partition(" WITH ")[0])
    if license_info and " WITH " in member and license_info.category == LicenseCategory.STRONG_COPYLEFT:
        return replace(
            license_info,
            category=LicenseCategory.WEAK_COPYLEFT,
            description="The exception lets code that only links to this library keep its own license; "
            "changes to the library itself stay under its copyleft.",
            obligations=[SHARE_SOURCE_OF_MODIFICATIONS, INCLUDE_LICENSE_TEXT],
            risks=[],
        )
    return license_info


class LicenseAnalyzer(Analyzer):
    name = "license_compliance"

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Analyze SBOM components for license compliance issues."""
        policy = license_policy_from_settings(settings)

        components = parsed_components or []
        issues: list[dict[str, Any]] = []
        component_licenses: list[dict[str, Any]] = []
        stats = {
            "total_components": len(components),
            **dict.fromkeys([*CATEGORY_STAT_KEY.values(), "unknown", "skipped"], 0),
        }

        settled = [
            (component, self._analyze_component(component, stats, issues, component_licenses, policy=policy))
            for component in components
        ]
        for conflict, is_transitive in compatibility.check_license_compatibility(settled, policy):
            self._emit_policy_issue(conflict, None, is_transitive, issues)

        return {"license_issues": issues, "summary": stats, "component_licenses": component_licenses}

    def _analyze_component(
        self,
        component: dict[str, Any],
        stats: dict[str, int],
        issues: list[dict[str, Any]],
        component_licenses: list[dict[str, Any]],
        *,
        policy: LicensePolicySchema,
    ) -> list[str]:
        """Classify and judge one component; return the licences it settled on for the conflict check."""
        # The distro descriptor is kept for EOL detection; it is not a licensed dependency.
        if component.get("type") == "operating-system":
            stats["skipped"] += 1
            return []

        if policy.ignore_dev_dependencies and (component.get("scope") or "").lower() in NON_RUNTIME_SCOPES:
            stats["skipped"] += 1
            return []

        # Default to direct when unknown so unknown deps are never skipped or downgraded.
        is_transitive = not component.get("direct", True)
        if policy.ignore_transitive and is_transitive:
            stats["skipped"] += 1
            return []

        declared = component.get("license") or ""
        or_groups = normalizer.parse_license_expression(declared)
        # A linking exception such as Classpath lifts the copyleft the pair rules are about.
        excepted = {member.partition(" WITH ")[0] for group in or_groups for member in group if " WITH " in member}
        if len(or_groups) > 1:
            selected = self._analyze_or_expression(
                component,
                declared,
                or_groups,
                stats,
                issues,
                component_licenses,
                is_transitive=is_transitive,
                policy=policy,
            )
            return [license_id for license_id in selected if license_id not in excepted]

        members = or_groups[0] if or_groups else []
        if not members:
            stats["unknown"] += 1
            issues.append(evaluator.create_undeterminable_issue(component, []))
            return []

        # Keep the declared composite on each issue so the full license survives enrichment.
        raw_expression = declared if len(members) > 1 or " WITH " in members[0] else None
        lic_url = component.get("license_url")

        settled: list[str] = []
        unrecognized: list[str] = []
        for member in members:
            normalized = member.partition(" WITH ")[0]
            if normalized not in LICENSE_DATABASE and len(members) == 1:
                # A lone licence's URL is its own; with several, the one stored URL may belong to another.
                normalized = normalizer.extract_license_from_url(lic_url) or normalized
            license_info = classify_license(member, normalized)
            if not license_info:
                stats["unknown"] += 1
                unrecognized.append(normalized)
                continue

            settled.append(normalized)
            self._record_license(component, normalized, license_info, raw_expression, stats, component_licenses)
            issue = evaluator.evaluate_license(component, license_info, policy, lic_url)
            if issue:
                self._emit_policy_issue(issue, raw_expression, is_transitive, issues)

        if unrecognized:
            # Neither adjusted nor filtered by transitivity: the audit control reads presence, so
            # dropping the transitive ones would let it pass over components it cannot audit.
            issues.append(evaluator.create_undeterminable_issue(component, unrecognized))
        return [license_id for license_id in settled if license_id not in excepted]

    @staticmethod
    def _record_license(
        component: dict[str, Any],
        spdx_id: str,
        license_info: LicenseInfo,
        spdx_expression: str | None,
        stats: dict[str, int],
        component_licenses: list[dict[str, Any]],
    ) -> None:
        """Count the licence and classify it, regardless of the policy verdict."""
        stats[CATEGORY_STAT_KEY[license_info.category]] += 1
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
        component_licenses.append(entry)

    @staticmethod
    def _emit_policy_issue(
        issue: dict[str, Any],
        spdx_expression: str | None,
        is_transitive: bool,
        issues: list[dict[str, Any]],
    ) -> None:
        if spdx_expression:
            issue["spdx_expression"] = spdx_expression
        evaluator.apply_transitive_adjustment(issue, is_transitive)
        if evaluator.should_include_finding(issue, is_transitive):
            issues.append(issue)

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
    ) -> list[str]:
        """Resolve an OR-expression to the alternative a consumer would take, or report it undeterminable."""
        readable_groups, unreadable = compatibility.partition_or_groups(or_groups)
        selected, member_issues = self._select_or_alternative(component, readable_groups, policy)

        if selected is None or (
            unreadable and not all(evaluator.is_acceptable_under_policy(issue) for issue in member_issues)
        ):
            # No alternative is both readable and acceptable, so the expression settles nothing:
            # an acceptable licence may sit behind the identifier we do not recognise.
            stats["unknown"] += 1
            rejected = list(dict.fromkeys(lic_id for group in readable_groups for lic_id in group))
            issues.append(evaluator.create_undeterminable_issue(component, unreadable, rejected))
            return []

        for lic_id in selected:
            self._record_license(component, lic_id, LICENSE_DATABASE[lic_id], spdx_expr, stats, component_licenses)
        for issue in member_issues:
            self._emit_policy_issue(issue, spdx_expr, is_transitive, issues)
        return selected

    @staticmethod
    def _select_or_alternative(
        component: dict[str, Any],
        readable_groups: list[list[str]],
        policy: LicensePolicySchema,
    ) -> tuple[list[str] | None, list[dict[str, Any]]]:
        """Choose the OR-alternative a consumer would take: lowest worst-member severity, then lowest restrictiveness,
        then declaration order. Returns the chosen group and its members' issues, or (None, []) when none is readable."""
        candidates: list[tuple[tuple[int, int], list[str], list[dict[str, Any]]]] = []
        for and_group in readable_groups:
            verdicts = [evaluator.evaluate_license(component, LICENSE_DATABASE[lic_id], policy) for lic_id in and_group]
            rank = (
                # No issue ranks below every severity, INFO included.
                max(get_severity_value(issue["severity"]) if issue else -1 for issue in verdicts),
                max(CATEGORY_RESTRICTIVENESS[LICENSE_DATABASE[lic_id].category] for lic_id in and_group),
            )
            candidates.append((rank, and_group, [issue for issue in verdicts if issue]))

        if not candidates:
            return None, []
        _, best_group, best_issues = min(candidates, key=lambda candidate: candidate[0])
        return best_group, best_issues

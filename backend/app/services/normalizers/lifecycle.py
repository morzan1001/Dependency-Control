from typing import TYPE_CHECKING, Any

from app.models.finding import Finding, FindingType, Severity
from app.schemas.finding_details import EolDetails, OutdatedDetails
from app.services.normalizers.utils import FindingIdPrefix, build_finding_id, safe_get, safe_severity

if TYPE_CHECKING:
    from app.services.aggregation import ResultAggregator


def normalize_outdated(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    for item in result.get("outdated_dependencies") or []:
        component = safe_get(item, "component", "unknown")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("OUTDATED", component),
                type=FindingType.OUTDATED,
                severity=safe_severity(item.get("severity"), default=Severity.INFO),
                component=component,
                version=item.get("current_version"),
                description=item.get("message") or f"Outdated: {component}",
                scanners=["outdated_packages"],
                details=OutdatedDetails(fixed_version=item.get("latest_version")).model_dump(exclude_none=True),
            ),
            source=source,
        )

    for item in result.get("ahead_of_default") or []:
        component = safe_get(item, "component", "unknown")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("OUTDATED", component, "ahead"),
                type=FindingType.OUTDATED,
                severity=Severity.INFO,
                component=component,
                version=item.get("current_version"),
                description=item.get("message") or f"Ahead of default: {component}",
                scanners=["outdated_packages"],
                details=OutdatedDetails(
                    default_version=item.get("default_version"),
                    ahead_of_default=True,
                ).model_dump(exclude_none=True),
            ),
            source=source,
        )


def normalize_eol(aggregator: "ResultAggregator", result: dict[str, Any], source: str | None = None) -> None:
    for item in result.get("eol_issues") or []:
        eol_info = item.get("eol_info") or {}
        eol_date = eol_info.get("eol")
        cycle = eol_info.get("cycle") or "unknown"
        latest = eol_info.get("latest")
        component = safe_get(item, "component", "unknown")

        recommended = eol_info.get("recommended_version")
        recommended_cycle = eol_info.get("recommended_cycle")

        # endoflife.date marks an undated end of life with ``eol: true``.
        reached = f"reached EOL on {eol_date}" if isinstance(eol_date, str) else "reached EOL"
        if item.get("distro_build"):
            advice = "The distribution may still backport fixes to this build; a newer base image leaves the cycle"
        elif recommended_cycle:
            advice = f"Upgrade to {recommended} (cycle {recommended_cycle})"
        else:
            advice = f"Latest: {latest}"
        description = f"End of Life: Version cycle {cycle} {reached}. {advice}"

        aggregator.add_finding(
            Finding(
                id=build_finding_id(FindingIdPrefix.EOL, component, cycle),
                type=FindingType.EOL,
                severity=safe_severity(item.get("severity"), default=Severity.HIGH),
                component=component,
                version=item.get("version"),
                description=description,
                scanners=["end_of_life"],
                details=EolDetails(
                    fixed_version=recommended,
                    eol_date=eol_date,
                    cycle=cycle,
                    recommended_cycle=recommended_cycle,
                    link=eol_info.get("link"),
                    lts=eol_info.get("lts"),
                ).model_dump(exclude_none=True),
            ),
            source=source,
        )

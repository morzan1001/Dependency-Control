from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.recommendation.common import ModelOrDict, get_attr, name_some, sample_components, severity_impact

_SECRET_TYPES_NAMED = 5

# Scoring marks a secret LOW when it is unverified and gone from the current tree.
_SECRET_CARDS = (
    (
        False,
        Priority.CRITICAL,
        "Rotate Exposed Credentials",
        "Immediately rotate all affected credentials and remove from code.",
        (
            "Immediately rotate/regenerate all exposed credentials",
            "Update applications using these credentials",
            "Remove secrets from code and use environment variables or secret managers",
            "Add secret patterns to .gitignore and pre-commit hooks",
            "Scan git history for previously committed secrets",
        ),
    ),
    (
        True,
        Priority.LOW,
        "Rotate Credentials Left in Git History",
        "They are no longer in the current tree and unverified: rotate if still valid and purge from git history.",
        (
            "Check whether each credential is still valid",
            "Rotate/regenerate the ones that are",
            "Purge the secrets from git history",
            "Add secret patterns to pre-commit hooks",
        ),
    ),
)


def process_secrets(findings: list[ModelOrDict]) -> list[Recommendation]:
    """One card for live secrets and one for secrets scored LOW, each at its own priority."""
    recommendations = []
    for deprioritized, priority, title, advice, steps in _SECRET_CARDS:
        group = [f for f in findings if (get_attr(f, "severity") == "LOW") is deprioritized]
        if not group:
            continue

        secret_types = sorted(
            {
                str(details.get("detector_name") or details.get("detector"))
                for details in (get_attr(f, "details", {}) for f in group)
            }
        )
        files = sorted({component for f in group if (component := get_attr(f, "component", ""))})
        files_shown, files_total = sample_components(files)

        recommendations.append(
            Recommendation(
                type=RecommendationType.ROTATE_SECRETS,
                priority=priority,
                title=title,
                description=(
                    f"Found {len(group)} exposed secrets/credentials in {len(files)} files. "
                    f"These include: {name_some(secret_types, _SECRET_TYPES_NAMED)}. {advice}"
                ),
                impact=severity_impact(get_attr(f, "severity", "UNKNOWN") for f in group),
                affected_components=files_shown,
                affected_components_total=files_total,
                action={
                    "type": "rotate_secrets",
                    "secret_types": secret_types,
                    "files": files_shown,
                    "files_total": files_total,
                    "steps": list(steps),
                },
                effort="high",
            )
        )

    return recommendations

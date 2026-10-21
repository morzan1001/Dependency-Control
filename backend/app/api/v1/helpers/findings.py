from typing import Literal, get_args

from app.models.finding import CRYPTO_FINDING_TYPES, FindingType

FindingCategory = Literal["security", "secret", "sast", "compliance", "quality", "crypto", "other"]

TYPE_CATEGORY_MAP: dict[str, FindingCategory] = {
    "vulnerability": "security",
    "malware": "security",
    "secret": "secret",
    "sast": "sast",
    "iac": "sast",
    # OpenGrep's crypto-misuse rules raise it, so it lists beside that scanner's other findings.
    FindingType.CRYPTO_KEY_MANAGEMENT.value: "sast",
    "license": "compliance",
    "eol": "compliance",
    "outdated": "quality",
    "quality": "quality",
    **dict.fromkeys(sorted(CRYPTO_FINDING_TYPES - {FindingType.CRYPTO_KEY_MANAGEMENT.value}), "crypto"),
    "system_warning": "other",
    "other": "other",
}


def get_category_type_filter(category: FindingCategory) -> dict[str, list[str]]:
    return {"$in": [finding_type for finding_type, owner in TYPE_CATEGORY_MAP.items() if owner == category]}


def get_category_for_type(finding_type: str) -> FindingCategory:
    return TYPE_CATEGORY_MAP.get(finding_type, "other")


def aggregate_stats_by_category(type_counts: list) -> dict[str, int]:
    stats: dict[str, int] = dict.fromkeys(get_args(FindingCategory), 0)
    for item in type_counts:
        finding_type = item["_id"]
        count = item["count"]
        category = get_category_for_type(finding_type)
        stats[category] += count

    return stats

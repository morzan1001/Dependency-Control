from typing import List, Dict, Any

from app.schemas.recommendation import (
    Recommendation,
    RecommendationType,
    Priority,
)


def analyze_deep_dependency_chains(
    dependencies: List[Dict[str, Any]], max_dependency_depth: int = 8
) -> List[Recommendation]:
    """
    Identify dependencies with very deep transitive chains.
    Deep chains increase supply chain risk and make updates harder.
    """
    recommendations = []

    # Build a simple depth map based on parent_components
    depth_map = {}  # purl/name -> estimated depth

    # First pass: direct deps have depth 1
    for dep in dependencies:
        key = dep.get("purl") or f"{dep.get('name')}@{dep.get('version')}"
        if dep.get("direct", False):
            depth_map[key] = 1

    # Iterative depth calculation
    for _ in range(10):  # Max iterations
        changed = False
        for dep in dependencies:
            key = dep.get("purl") or f"{dep.get('name')}@{dep.get('version')}"
            parents = dep.get("parent_components", [])

            if key in depth_map:
                continue

            # Calculate depth from parents
            parent_depths = []
            for parent in parents:
                if parent in depth_map:
                    parent_depths.append(depth_map[parent])

            if parent_depths:
                depth_map[key] = max(parent_depths) + 1
                changed = True

        if not changed:
            break

    # Find deeply nested deps
    deep_deps = []
    for dep in dependencies:
        key = dep.get("purl") or f"{dep.get('name')}@{dep.get('version')}"
        depth = depth_map.get(key, 0)

        if depth > max_dependency_depth:
            deep_deps.append(
                {
                    "name": dep.get("name"),
                    "version": dep.get("version"),
                    "depth": depth,
                    "parents": dep.get("parent_components", [])[:3],
                }
            )

    if deep_deps:
        # Sort by depth
        deep_deps.sort(key=lambda x: x["depth"], reverse=True)
        max_depth = deep_deps[0]["depth"] if deep_deps else 0

        recommendations.append(
            Recommendation(
                type=RecommendationType.DEEP_DEPENDENCY_CHAIN,
                priority=Priority.LOW,
                title=f"Deep dependency chains detected (max depth: {max_depth})",
                description=f"{len(deep_deps)} dependencies are nested more than {max_dependency_depth} levels deep. Deep chains increase supply chain attack surface and make dependency updates more complex.",
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": len([d for d in deep_deps if d["depth"] > 7]),
                    "low": len([d for d in deep_deps if d["depth"] <= 7]),
                    "total": len(deep_deps),
                },
                affected_components=[
                    f"{d['name']}@{d['version']} (depth: {d['depth']})"
                    for d in deep_deps[:10]
                ],
                action={
                    "type": "reduce_chain_depth",
                    "suggestions": [
                        "Consider using packages with fewer transitive dependencies",
                        "Evaluate if some functionality can be implemented directly",
                        "Look for alternative packages with shallower dependency trees",
                    ],
                    "deepest_chains": [
                        {
                            "package": d["name"],
                            "depth": d["depth"],
                            "chain_preview": " → ".join(d["parents"][:3]),
                        }
                        for d in deep_deps[:5]
                    ],
                },
                effort="high",
            )
        )

    return recommendations


def analyze_duplicate_packages(
    dependencies: List[Dict[str, Any]],
) -> List[Recommendation]:
    """
    Detect packages that likely provide similar/duplicate functionality.
    """
    recommendations = []

    # Groups of packages that often duplicate functionality
    similar_packages = [
        {
            "category": "HTTP Clients",
            "packages": [
                "axios",
                "node-fetch",
                "got",
                "request",
                "superagent",
                "ky",
            ],
            "suggestion": "Consider standardizing on one HTTP client (axios or node-fetch recommended)",
        },
        {
            "category": "Date/Time Libraries",
            "packages": ["moment", "dayjs", "date-fns", "luxon"],
            "suggestion": "Consider using only one date library (dayjs or date-fns recommended)",
        },
        {
            "category": "Utility Libraries",
            "packages": ["lodash", "underscore", "ramda"],
            "suggestion": "Modern JavaScript often doesn't need these - consider native methods",
        },
        {
            "category": "State Management",
            "packages": ["redux", "mobx", "recoil", "zustand", "jotai", "valtio"],
            "suggestion": "Multiple state management libraries may indicate architecture issues",
        },
        {
            "category": "CSS-in-JS",
            "packages": [
                "styled-components",
                "emotion",
                "@emotion/react",
                "@emotion/styled",
                "glamor",
            ],
            "suggestion": "Standardize on one CSS-in-JS solution",
        },
        {
            "category": "Form Libraries",
            "packages": ["formik", "react-hook-form", "final-form"],
            "suggestion": "Consider using only one form library (react-hook-form recommended)",
        },
        {
            "category": "Testing Assertion",
            "packages": ["chai", "expect", "should", "assert"],
            "suggestion": "Use Jest's built-in expect or standardize on one assertion library",
        },
    ]

    dep_names = {dep.get("name", "").lower() for dep in dependencies}

    duplicates_found = []
    for group in similar_packages:
        matches = [p for p in group["packages"] if p.lower() in dep_names]
        if len(matches) >= 2:
            duplicates_found.append(
                {
                    "category": group["category"],
                    "found": matches,
                    "suggestion": group["suggestion"],
                }
            )

    if duplicates_found:
        recommendations.append(
            Recommendation(
                type=RecommendationType.DUPLICATE_FUNCTIONALITY,
                priority=Priority.LOW,
                title=f"Potential duplicate packages in {len(duplicates_found)} categories",
                description="Multiple packages providing similar functionality were detected. Consolidating to one package per category can reduce bundle size and maintenance burden.",
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": len(duplicates_found),
                    "total": len(duplicates_found),
                },
                affected_components=[
                    f"{d['category']}: {', '.join(d['found'])}"
                    for d in duplicates_found
                ],
                action={
                    "type": "consolidate_packages",
                    "duplicates": duplicates_found,
                },
                effort="medium",
            )
        )

    return recommendations

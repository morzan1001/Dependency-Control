"""CVSS v3.x base-score computation from a vector string.

OSV rates a vulnerability with a vector and no numeric score — a census of 242 records
fetched for real production purls found 217 of 217 severity entries to be vector strings —
so a vector we cannot score is a rating thrown away.

Implemented in-house rather than by adding a dependency: the v3.x base formula is short,
exactly specified and fully testable against published scores, and this runs inside the
ingest path of a security platform where a new transitive dependency needs its own decision.
"""

import math

_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_REQUIRED_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_REQUIRED_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

# v4.0 needs a 270-entry MacroVector lookup table; production carries 2 such entries in 217,
# and _severity_from_cvss_array falls through to the record's v3 entry when one exists.
SUPPORTED_PREFIXES = ("CVSS:3.0", "CVSS:3.1")


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A: the smallest one-decimal number greater than or equal to value."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def _parse_metrics(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, separator, value = part.partition(":")
        if separator:
            metrics[key] = value
    return metrics


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a CVSS v3.0/v3.1 vector; None when it is not a vector we can score."""
    text = vector.strip()
    if not text.startswith(SUPPORTED_PREFIXES):
        return None

    metrics = _parse_metrics(text)
    try:
        scope_changed = metrics["S"] == "C"
        privileges = _PRIVILEGES_REQUIRED_CHANGED if scope_changed else _PRIVILEGES_REQUIRED_UNCHANGED
        exploitability = (
            8.22
            * _ATTACK_VECTOR[metrics["AV"]]
            * _ATTACK_COMPLEXITY[metrics["AC"]]
            * privileges[metrics["PR"]]
            * _USER_INTERACTION[metrics["UI"]]
        )
        impact_sub_score = 1 - ((1 - _IMPACT[metrics["C"]]) * (1 - _IMPACT[metrics["I"]]) * (1 - _IMPACT[metrics["A"]]))
    except KeyError:
        return None

    if scope_changed:
        impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02) ** 15
    else:
        impact = 6.42 * impact_sub_score

    if impact <= 0:
        return 0.0

    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))

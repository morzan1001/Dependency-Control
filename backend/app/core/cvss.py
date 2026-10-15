import math

from cvss import CVSS4
from cvss.exceptions import CVSSError

_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_REQUIRED_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_REQUIRED_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_V3_PREFIXES = ("CVSS:3.0", "CVSS:3.1")
_V4_PREFIX = "CVSS:4.0"


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A: the smallest one-decimal number greater than or equal to value."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def _parse_metrics(vector: str) -> dict[str, str] | None:
    """A repeated metric yields None, as the reference implementation rejects such a vector rather than picking one."""
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, separator, value = part.partition(":")
        if not separator:
            continue
        if key in metrics:
            return None
        metrics[key] = value
    return metrics


def cvss3_base_score(vector: str) -> float | None:
    text = vector.strip()
    if not text.startswith(_V3_PREFIXES):
        return None

    metrics = _parse_metrics(text)
    if metrics is None:
        return None
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


def cvss4_base_score(vector: str) -> float | None:
    text = vector.strip()
    if not text.startswith(_V4_PREFIX):
        return None
    try:
        return float(CVSS4(text).base_score)
    except (CVSSError, ValueError, TypeError, KeyError):
        return None


def cvss_base_score(vector: str) -> float | None:
    text = vector.strip()
    if text.startswith(_V4_PREFIX):
        return cvss4_base_score(text)
    return cvss3_base_score(text)

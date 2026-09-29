from collections.abc import Iterable

from app.core.constants import (
    EPSS_HIGH_THRESHOLD,
    EPSS_MEDIUM_THRESHOLD,
    EXPLOIT_MATURITY_ORDER,
    SEVERITY_CALCULATED_RISK_SCORES,
)
from app.core.risk_scoring import is_deprioritized_secret
from app.models.finding import Severity
from app.schemas.enrichment import VulnerabilityEnrichment


def fold_enrichments(enrichments: Iterable[VulnerabilityEnrichment]) -> VulnerabilityEnrichment | None:
    """The worst case across CVEs: highest EPSS, risk and maturity, and the KEV entry due first."""
    items = list(enrichments)
    if not items:
        return None
    epss = max((e for e in items if e.epss_score is not None), key=lambda e: (e.epss_score, e.cve), default=None)
    kev = min((e for e in items if e.is_kev), key=lambda e: (e.kev_due_date or "~", e.cve), default=None)
    return VulnerabilityEnrichment(
        cve=min(e.cve for e in items),
        epss_score=epss.epss_score if epss else None,
        epss_percentile=epss.epss_percentile if epss else None,
        epss_date=epss.epss_date if epss else None,
        is_kev=kev is not None,
        kev_date_added=kev.kev_date_added if kev else None,
        kev_due_date=kev.kev_due_date if kev else None,
        kev_required_action=kev.kev_required_action if kev else None,
        kev_ransomware_use=any(e.kev_ransomware_use for e in items),
        exploit_maturity=max((e.exploit_maturity for e in items), key=lambda m: EXPLOIT_MATURITY_ORDER.get(m, 0)),
        risk_score=max(e.risk_score for e in items),
    )


def _calculate_epss_contribution(epss_score: float) -> float:
    """EPSS 0..1 → 0..25 points, piecewise linear, continuous at bucket boundaries (0@0, 10@MEDIUM, 20@HIGH, 25@1.0)."""
    if epss_score <= 0:
        return 0.0
    if epss_score >= 1.0:
        return 25.0
    if epss_score >= EPSS_HIGH_THRESHOLD:
        return 20.0 + (epss_score - EPSS_HIGH_THRESHOLD) * (5.0 / (1.0 - EPSS_HIGH_THRESHOLD))
    if epss_score >= EPSS_MEDIUM_THRESHOLD:
        return 10.0 + (epss_score - EPSS_MEDIUM_THRESHOLD) * (10.0 / (EPSS_HIGH_THRESHOLD - EPSS_MEDIUM_THRESHOLD))
    return epss_score * (10.0 / EPSS_MEDIUM_THRESHOLD)


def _apply_reachability_modifier(
    score: float,
    is_reachable: bool | None,
    reachability_level: str | None,
) -> float:
    """Scale by reachability: 0.4 if unreachable, 1.1 if confirmed, else identity (not 0 — analysis is imperfect)."""
    if is_reachable is None and reachability_level is None:
        return score
    if is_reachable is False or reachability_level == "unreachable":
        return score * 0.4
    if reachability_level == "confirmed":
        return score * 1.1
    return score


def calculate_risk_score(
    cvss_score: float | None,
    epss_score: float | None,
    is_kev: bool,
    kev_ransomware: bool,
    is_reachable: bool | None = None,
    reachability_level: str | None = None,
) -> float:
    """Combined 0..100 risk = CVSS (<=40, 20 default) + EPSS (<=25) + KEV (+20) + ransomware (+5), then reachability multiplier, capped at 100."""
    score = (cvss_score / 10.0) * 40 if cvss_score is not None else 20.0
    if epss_score is not None:
        score += _calculate_epss_contribution(epss_score)
    if is_kev:
        score += 20
    if kev_ransomware:
        score += 5
    score = _apply_reachability_modifier(score, is_reachable, reachability_level)
    return min(score, 100.0)


def calculate_adjusted_risk_score(
    base_risk_score: float,
    is_reachable: bool | None = None,
    reachability_level: str | None = None,
) -> float:
    """Apply only the reachability modifier to an already-computed risk score."""
    if is_reachable is None and reachability_level is None:
        return base_risk_score
    if is_reachable is False or reachability_level == "unreachable":
        return base_risk_score * 0.4
    if reachability_level == "confirmed":
        return min(base_risk_score * 1.1, 100.0)
    return base_risk_score


def map_reachability_level_to_modifier(
    analysis_level: str | None,
    is_reachable: bool | None,
) -> str | None:
    """Map reachability enrichment (analysis_level + is_reachable) to the scoring modifier vocab: not-reachable -> "unreachable", symbol-level reachable -> "confirmed", else identity."""
    if analysis_level in ("confirmed", "unreachable"):
        return analysis_level
    if is_reachable is False:
        return "unreachable"
    if is_reachable is True and analysis_level == "symbol":
        return "confirmed"
    return None


def calculate_secret_risk_score(
    verified: bool | None,
    in_current_tree: bool | None,
) -> tuple[float, float]:
    """CRITICAL-anchor (risk_score, adjusted_risk_score): verified secrets stay urgent regardless of tree state (already exposed until rotated), else 0.4x if gone from the tree."""
    base = SEVERITY_CALCULATED_RISK_SCORES["CRITICAL"]
    if verified is True:
        modifier = 1.1
    elif in_current_tree is False:
        modifier = 0.4
    else:
        modifier = 1.0
    adjusted = min(base * modifier, 100.0)
    return base, adjusted


def calculate_secret_severity(verified: bool | None, in_current_tree: bool | None) -> Severity:
    """A verified credential is a live leak until rotated, so it stays CRITICAL even once the file is gone."""
    return Severity.LOW if is_deprioritized_secret(verified, in_current_tree) else Severity.CRITICAL

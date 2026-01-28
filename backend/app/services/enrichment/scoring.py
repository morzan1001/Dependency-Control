from typing import Optional

from app.core.constants import EPSS_HIGH_THRESHOLD, EPSS_MEDIUM_THRESHOLD


def calculate_exploit_maturity(
    is_kev: bool, kev_ransomware: bool, epss_score: Optional[float]
) -> str:
    """
    Determine exploit maturity level.

    Levels:
    - weaponized: Active ransomware use
    - active: In CISA KEV (confirmed active exploitation)
    - high: EPSS >= HIGH_THRESHOLD (10% chance of exploitation)
    - medium: EPSS >= MEDIUM_THRESHOLD (1% chance)
    - low: EPSS < MEDIUM_THRESHOLD
    - unknown: No data
    """
    if kev_ransomware:
        return "weaponized"
    if is_kev:
        return "active"
    if epss_score is not None:
        if epss_score >= EPSS_HIGH_THRESHOLD:
            return "high"
        if epss_score >= EPSS_MEDIUM_THRESHOLD:
            return "medium"
        return "low"
    return "unknown"


def calculate_risk_score(
    cvss_score: Optional[float],
    epss_score: Optional[float],
    is_kev: bool,
    kev_ransomware: bool,
    is_reachable: Optional[bool] = None,
    reachability_level: Optional[str] = None,
) -> float:
    """
    Calculate a combined risk score (0-100) considering:
    - CVSS score (severity/impact)
    - EPSS score (likelihood of exploitation in the wild)
    - KEV status (confirmed active exploitation)
    - Reachability (is the vulnerable code actually used?)

    Formula (revised for realistic prioritization):
    - Base: CVSS normalized to 0-40 (severity is important but not everything)
    - EPSS contribution: up to +25 points (exploitation probability is key)
    - KEV bonus: +20 points (actively exploited = urgent)
    - Ransomware bonus: +5 points (known ransomware = very urgent)
    - Reachability modifier: multiplier based on whether code is used
    """
    score = 0.0

    # CVSS contribution (0-40 points)
    # CVSS tells us the IMPACT if exploited, but not likelihood
    if cvss_score is not None:
        score += (cvss_score / 10.0) * 40
    else:
        # Default to medium if no CVSS
        score += 20

    # EPSS contribution (0-25 points)
    # EPSS tells us the PROBABILITY of exploitation in the next 30 days
    if epss_score is not None:
        # Non-linear scaling: high EPSS scores get disproportionately more weight
        if epss_score >= EPSS_HIGH_THRESHOLD:  # Top 10% - very likely to be exploited
            epss_contribution = 20 + (min(epss_score, 1.0) * 5)
        elif epss_score >= EPSS_MEDIUM_THRESHOLD:  # 1-10% - moderate likelihood
            epss_contribution = 10 + (epss_score * 100)  # 10-20 points
        else:  # < 1% - low likelihood
            epss_contribution = epss_score * 1000  # 0-10 points
        score += min(epss_contribution, 25)

    # KEV bonus - confirmed active exploitation is critical
    if is_kev:
        score += 20

    # Ransomware bonus - known ransomware campaigns need immediate attention
    if kev_ransomware:
        score += 5

    # Apply reachability modifier
    # If we know the code is unreachable, significantly reduce the score
    # If reachable or unknown, keep the score as-is or boost it slightly
    if is_reachable is not None or reachability_level is not None:
        if is_reachable is False or reachability_level == "unreachable":
            # Unreachable: reduce score by 60% (still keep some risk as analysis isn't perfect)
            score *= 0.4
        elif is_reachable is True or reachability_level in ("confirmed", "likely"):
            # Confirmed reachable: slight boost
            if reachability_level == "confirmed":
                score *= 1.1  # 10% boost for confirmed reachability
            # "likely" gets no modifier - baseline score
    # If reachability is unknown/not analyzed, no modifier applied

    return min(score, 100.0)


def calculate_adjusted_risk_score(
    base_risk_score: float,
    is_reachable: Optional[bool] = None,
    reachability_level: Optional[str] = None,
) -> float:
    """
    Calculate an adjusted risk score considering reachability.
    Use this when reachability is analyzed separately from EPSS/KEV.
    """
    if is_reachable is None and reachability_level is None:
        return base_risk_score

    if is_reachable is False or reachability_level == "unreachable":
        return base_risk_score * 0.4
    elif reachability_level == "confirmed":
        return min(base_risk_score * 1.1, 100.0)

    return base_risk_score

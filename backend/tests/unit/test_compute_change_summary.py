from app.models.crypto_policy import CryptoPolicy
from app.models.finding import FindingType, Severity
from app.schemas.crypto_policy import CryptoPolicySource, CryptoRule
from app.services.audit.history import compute_change_summary


def _rule(rule_id, enabled=True, severity=Severity.HIGH):
    return CryptoRule(
        rule_id=rule_id,
        name=rule_id,
        description="",
        finding_type=FindingType.CRYPTO_WEAK_ALGORITHM,
        default_severity=severity,
        source=CryptoPolicySource.CUSTOM,
        enabled=enabled,
    )


def _policy(*rules, scope="system", version=1):
    return CryptoPolicy(scope=scope, rules=list(rules), version=version)


def test_initial_policy_summary():
    new = _policy(_rule("a"), _rule("b"))
    assert compute_change_summary(None, new) == "Initial policy (2 rules)"


def test_empty_diff():
    rules = [_rule("a"), _rule("b")]
    old = _policy(*rules)
    new = _policy(*rules, version=2)
    summary = compute_change_summary(old, new)
    assert "no effective changes" in summary.lower()


def test_add_rule():
    old = _policy(_rule("a"))
    new = _policy(_rule("a"), _rule("b"), version=2)
    summary = compute_change_summary(old, new)
    assert "added 1" in summary.lower()


def test_remove_rule():
    old = _policy(_rule("a"), _rule("b"))
    new = _policy(_rule("a"), version=2)
    summary = compute_change_summary(old, new)
    assert "removed 1" in summary.lower()


def test_toggle_enabled():
    old = _policy(_rule("a", enabled=True), _rule("b", enabled=True))
    new = _policy(_rule("a", enabled=False), _rule("b", enabled=True), version=2)
    summary = compute_change_summary(old, new)
    assert "toggled enabled on 1" in summary.lower()


def test_modify_severity():
    old = _policy(_rule("a", severity=Severity.HIGH))
    new = _policy(_rule("a", severity=Severity.LOW), version=2)
    summary = compute_change_summary(old, new)
    assert "modified 1" in summary.lower()


def test_combined_changes():
    old = _policy(_rule("a", enabled=True), _rule("b"))
    new = _policy(_rule("a", enabled=False), _rule("c"), version=2)
    summary = compute_change_summary(old, new)
    assert "added 1" in summary.lower()
    assert "removed 1" in summary.lower()
    assert "toggled enabled on 1" in summary.lower()


def test_summary_length_capped():
    old = _policy(*[_rule(f"r{i}") for i in range(50)])
    new = _policy(version=2)
    summary = compute_change_summary(old, new)
    assert len(summary) <= 200

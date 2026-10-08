def rule_dict(rule_id: str) -> dict:
    """A custom crypto rule in the shape the policy endpoints accept."""
    return {
        "rule_id": rule_id,
        "name": rule_id,
        "description": "",
        "finding_type": "crypto_weak_algorithm",
        "default_severity": "HIGH",
        "source": "custom",
        "match_name_patterns": ["X"],
        "enabled": True,
    }

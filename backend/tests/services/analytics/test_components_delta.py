from app.services.analytics.components_delta import component_identity_key


def test_identity_strips_version_from_purl():
    # purl with version → version stripped
    assert component_identity_key({"purl": "pkg:npm/react@17.0.2", "name": "react"}) == \
        ("npm", "react")


def test_identity_with_namespace():
    assert component_identity_key({"purl": "pkg:maven/org.springframework/spring-core@5.3", "name": "spring-core"}) == \
        ("maven:org.springframework", "spring-core")


def test_identity_without_purl_uses_name_and_type():
    assert component_identity_key({"name": "react", "type": "npm"}) == ("npm", "react")


def test_identity_without_purl_or_type():
    assert component_identity_key({"name": "react"}) == ("unknown", "react")

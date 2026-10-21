import pytest

_AUTHORIZATION_STATUSES = {"200", "403", "404", "422"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "as_admin"),
    [
        ("/api/v1/crypto-policies/system/audit/999", True),
        ("/api/v1/projects/p/crypto-policy/audit/999", False),
        ("/api/v1/projects/p/license-policy/audit/999", False),
    ],
)
async def test_every_unknown_audit_version_is_one_404_naming_it(
    client, admin_auth_headers, owner_auth_headers_proj, path, as_admin
):
    resp = await client.get(path, headers=admin_auth_headers if as_admin else owner_auth_headers_proj)

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Version 999 not found"


@pytest.mark.parametrize(
    ("method", "path", "statuses"),
    [
        ("get", "/api/v1/projects/{project_id}/crypto-policy/audit", _AUTHORIZATION_STATUSES),
        ("get", "/api/v1/projects/{project_id}/crypto-policy/audit/{version}", _AUTHORIZATION_STATUSES),
        ("delete", "/api/v1/projects/{project_id}/crypto-policy/audit", {"400", *_AUTHORIZATION_STATUSES}),
        ("get", "/api/v1/projects/{project_id}/license-policy/audit", _AUTHORIZATION_STATUSES),
        ("get", "/api/v1/projects/{project_id}/license-policy/audit/{version}", _AUTHORIZATION_STATUSES),
    ],
)
def test_each_project_audit_route_documents_the_access_check_it_answers(method, path, statuses):
    from app.main import app

    assert set(app.openapi()["paths"][path][method]["responses"]) == statuses

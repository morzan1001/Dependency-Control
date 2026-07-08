import pytest

from app.services.analytics.components_delta import (
    component_identity_key,
    compute_components_delta,
)


def test_identity_strips_version_from_purl():
    assert component_identity_key({"purl": "pkg:npm/react@17.0.2", "name": "react"}) == ("npm", "react")


def test_identity_with_namespace():
    assert component_identity_key({"purl": "pkg:maven/org.springframework/spring-core@5.3", "name": "spring-core"}) == (
        "maven:org.springframework",
        "spring-core",
    )


def test_identity_unencoded_npm_scope_does_not_collapse():
    # SBOM generators that emit the scope '@' unencoded must not collapse every
    # scoped package to the same identity by splitting on the first '@'.
    core = component_identity_key({"purl": "pkg:npm/@angular/core@1.2.3"})
    router = component_identity_key({"purl": "pkg:npm/@angular/router@1.2.3"})
    assert core == ("npm:@angular", "core")
    assert router == ("npm:@angular", "router")
    assert core != router


def test_identity_unencoded_npm_scope_without_version():
    # No version present: the only '@' is the scope, which must be preserved.
    assert component_identity_key({"purl": "pkg:npm/@angular/core"}) == ("npm:@angular", "core")


def test_identity_strips_qualifiers_and_subpath():
    assert component_identity_key({"purl": "pkg:npm/react@17.0.2?foo=bar#sub"}) == ("npm", "react")


def test_identity_without_purl_uses_name_and_type():
    assert component_identity_key({"name": "react", "type": "npm"}) == ("npm", "react")


def test_identity_without_purl_or_type():
    assert component_identity_key({"name": "react"}) == ("unknown", "react")


@pytest.mark.asyncio
async def test_components_added_removed_changed(db):
    await db["dependencies"].insert_many(
        [
            {
                "_id": "a1",
                "project_id": "p1",
                "scan_id": "sa",
                "name": "react",
                "version": "17.0.2",
                "purl": "pkg:npm/react@17.0.2",
                "license": "MIT",
                "type": "npm",
            },
            {
                "_id": "a2",
                "project_id": "p1",
                "scan_id": "sa",
                "name": "removed-pkg",
                "version": "1.0",
                "purl": "pkg:npm/removed-pkg@1.0",
                "license": "MIT",
                "type": "npm",
            },
            {
                "_id": "b1",
                "project_id": "p1",
                "scan_id": "sb",
                "name": "react",
                "version": "18.2.0",
                "purl": "pkg:npm/react@18.2.0",
                "license": "MIT",
                "type": "npm",
            },
            {
                "_id": "b2",
                "project_id": "p1",
                "scan_id": "sb",
                "name": "new-pkg",
                "version": "2.0",
                "purl": "pkg:npm/new-pkg@2.0",
                "license": "Apache-2.0",
                "type": "npm",
            },
        ]
    )
    resp = await compute_components_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change=None,
    )
    assert resp.totals.added == 1
    assert resp.totals.removed == 1
    assert resp.totals.changed == 1
    by_change = {i.change: i for i in resp.items}
    assert by_change["version_changed"].name == "react"
    assert by_change["version_changed"].from_version == "17.0.2"
    assert by_change["version_changed"].to_version == "18.2.0"
    assert by_change["added"].name == "new-pkg"
    assert by_change["removed"].name == "removed-pkg"


@pytest.mark.asyncio
async def test_components_license_change_only(db):
    await db["dependencies"].insert_many(
        [
            {
                "_id": "ca",
                "project_id": "p1",
                "scan_id": "sa",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
                "license": "MIT",
                "type": "npm",
            },
            {
                "_id": "cb",
                "project_id": "p1",
                "scan_id": "sb",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
                "license": "Apache-2.0",
                "type": "npm",
            },
        ]
    )
    resp = await compute_components_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change=None,
    )
    items = [i for i in resp.items if i.change == "license_changed"]
    assert len(items) == 1
    assert items[0].from_license == "MIT"
    assert items[0].to_license == "Apache-2.0"


@pytest.mark.asyncio
async def test_components_version_and_license_change_is_one_entry(db):
    await db["dependencies"].insert_many(
        [
            {
                "_id": "da",
                "project_id": "p1",
                "scan_id": "sa",
                "name": "axios",
                "version": "0.21.0",
                "purl": "pkg:npm/axios@0.21.0",
                "license": "MIT",
                "type": "npm",
            },
            {
                "_id": "db1",
                "project_id": "p1",
                "scan_id": "sb",
                "name": "axios",
                "version": "1.6.0",
                "purl": "pkg:npm/axios@1.6.0",
                "license": "Apache-2.0",
                "type": "npm",
            },
        ]
    )
    resp = await compute_components_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change=None,
    )
    # One item, counted under version_changed (per spec)
    matched = [i for i in resp.items if i.name == "axios"]
    assert len(matched) == 1
    assert matched[0].change == "version_changed"
    assert matched[0].from_license == "MIT"
    assert matched[0].to_license == "Apache-2.0"
    assert resp.totals.changed == 1


@pytest.mark.asyncio
async def test_components_change_filter_only_added(db):
    await db["dependencies"].insert_many(
        [
            {
                "_id": "ea",
                "project_id": "p1",
                "scan_id": "sa",
                "name": "old",
                "version": "1.0",
                "purl": "pkg:npm/old@1.0",
                "type": "npm",
            },
            {
                "_id": "eb",
                "project_id": "p1",
                "scan_id": "sb",
                "name": "new",
                "version": "1.0",
                "purl": "pkg:npm/new@1.0",
                "type": "npm",
            },
        ]
    )
    resp = await compute_components_delta(
        db,
        project_id="p1",
        from_scan="sa",
        to_scan="sb",
        page=1,
        page_size=50,
        change="added",
    )
    assert all(i.change == "added" for i in resp.items)
    assert len(resp.items) == 1

import pytest

from app.services.analytics.components_delta import compute_components_delta


@pytest.mark.asyncio
async def test_a_package_respelled_by_another_producer_is_a_version_change(db):
    """Identity is the package, however each SBOM spells its purl: PyPI folds case, npm scopes decode."""
    rows = [
        ("sa", "PyYAML", "5.4", "pkg:pypi/PyYAML@5.4"),
        ("sb", "pyyaml", "6.0.1", "pkg:pypi/pyyaml@6.0.1"),
        ("sa", "core", "16.2.0", "pkg:npm/%40angular/core@16.2.0"),
        ("sb", "@angular/core", "17.0.0", "pkg:npm/@angular/core@17.0.0"),
    ]
    await db["dependencies"].insert_many(
        [
            {"_id": f"r{n}", "project_id": "p1", "scan_id": scan, "name": name, "version": version, "purl": purl}
            for n, (scan, name, version, purl) in enumerate(rows)
        ]
    )

    resp = await compute_components_delta(
        db, project_id="p1", from_scan="sa", to_scan="sb", page=1, page_size=50, change=None
    )

    assert (resp.totals.added, resp.totals.removed, resp.totals.changed) == (0, 0, 2)


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


@pytest.mark.parametrize(
    ("before", "after", "totals"),
    [
        ("pkg:pypi/PyYAML@6.0", "pkg:pypi/pyyaml@6.0.1", (0, 0, 1)),
        ("pkg:pypi/zope.interface@5.0", "pkg:pypi/zope-interface@5.1", (0, 0, 1)),
        ("pkg:NPM/x@1.0.0", "pkg:npm/x@1.0.1", (0, 0, 1)),
        ("pkg:maven/g1/core@1.0", "pkg:maven/g2/core@1.1", (1, 1, 0)),
    ],
)
@pytest.mark.asyncio
async def test_a_respelled_package_is_one_version_change(db, before, after, totals):
    await db["dependencies"].insert_many(
        [
            {"_id": scan, "project_id": "p1", "scan_id": scan, "name": purl.split("/")[-1].split("@")[0], "purl": purl}
            | {"version": purl.rsplit("@", 1)[1]}
            for scan, purl in (("sa", before), ("sb", after))
        ]
    )

    resp = await compute_components_delta(
        db, project_id="p1", from_scan="sa", to_scan="sb", page=1, page_size=50, change=None
    )

    assert (resp.totals.added, resp.totals.removed, resp.totals.changed) == totals

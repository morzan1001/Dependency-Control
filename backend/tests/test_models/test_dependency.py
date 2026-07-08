"""Tests for Dependency model."""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models.dependency import Dependency


class TestDependencyModel:
    def _make_dependency(self, **overrides):
        defaults = {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "name": "requests",
            "version": "2.31.0",
        }
        defaults.update(overrides)
        return Dependency(**defaults)

    def test_minimal_valid(self):
        dep = self._make_dependency()
        assert dep.project_id == "proj-1"
        assert dep.scan_id == "scan-1"
        assert dep.name == "requests"
        assert dep.version == "2.31.0"

    def test_id_auto_generated(self):
        a = self._make_dependency()
        b = self._make_dependency()
        assert a.id is not None
        assert len(a.id) > 0
        assert a.id != b.id

    def test_type_defaults_to_unknown(self):
        dep = self._make_dependency()
        assert dep.type == "unknown"

    def test_direct_defaults_to_false(self):
        dep = self._make_dependency()
        assert dep.direct is False
        assert dep.direct_inferred is False

    def test_optional_string_fields_default_none(self):
        dep = self._make_dependency()
        assert dep.purl is None
        assert dep.license is None
        assert dep.license_url is None
        assert dep.scope is None
        assert dep.source_type is None
        assert dep.source_target is None
        assert dep.layer_digest is None
        assert dep.found_by is None
        assert dep.description is None
        assert dep.author is None
        assert dep.publisher is None
        assert dep.group is None
        assert dep.homepage is None
        assert dep.repository_url is None
        assert dep.download_url is None

    def test_list_fields_default_empty(self):
        dep = self._make_dependency()
        assert dep.parent_components == []
        assert dep.locations == []
        assert dep.cpes == []

    def test_dict_fields_default_empty(self):
        dep = self._make_dependency()
        assert dep.hashes == {}
        assert dep.properties == {}

    def test_created_at_auto_set(self):
        before = datetime.now(timezone.utc)
        dep = self._make_dependency()
        after = datetime.now(timezone.utc)
        assert before <= dep.created_at <= after

    def test_missing_required_field_rejected(self):
        with pytest.raises(ValidationError):
            Dependency(project_id="p1", scan_id="s1", version="1.0")

    def test_fully_populated(self):
        dep = self._make_dependency(
            purl="pkg:pypi/requests@2.31.0",
            type="pypi",
            license="Apache-2.0",
            license_url="https://example.com/license",
            scope="runtime",
            direct=True,
            direct_inferred=False,
            parent_components=["pkg:pypi/flask@3.0"],
            source_type="directory",
            source_target="/app",
            layer_digest="sha256:abc",
            found_by="python-pkg-cataloger",
            locations=["/app/requirements.txt"],
            cpes=["cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:*:*:*"],
            description="HTTP library",
            author="Kenneth Reitz",
            publisher="PSF",
            group=None,
            homepage="https://requests.readthedocs.io",
            repository_url="https://github.com/psf/requests",
            download_url="https://pypi.org/packages/requests-2.31.0.tar.gz",
            hashes={"sha256": "abcdef1234567890"},
            properties={"syft:cataloger": "python-pkg-cataloger"},
        )
        assert dep.purl == "pkg:pypi/requests@2.31.0"
        assert dep.type == "pypi"
        assert dep.direct is True
        assert len(dep.cpes) == 1
        assert dep.hashes["sha256"] == "abcdef1234567890"
        assert dep.properties["syft:cataloger"] == "python-pkg-cataloger"

    def test_custom_type_value(self):
        for pkg_type in ["maven", "npm", "pypi", "rpm", "deb", "go-module"]:
            dep = self._make_dependency(type=pkg_type)
            assert dep.type == pkg_type


class TestDependencyIdAlias:
    def _make_dependency(self, **overrides):
        defaults = {
            "project_id": "proj-1",
            "scan_id": "scan-1",
            "name": "requests",
            "version": "2.31.0",
        }
        defaults.update(overrides)
        return Dependency(**defaults)

    def test_model_dump_by_alias_contains_id(self):
        dep = self._make_dependency()
        dumped = dep.model_dump(by_alias=True)
        assert "_id" in dumped
        assert dumped["_id"] == dep.id

    def test_accepts_id_from_mongo(self):
        dep = Dependency(
            _id="dep-custom-id",
            project_id="p1",
            scan_id="s1",
            name="pkg",
            version="1.0",
        )
        assert dep.id == "dep-custom-id"

    def test_roundtrip_via_model_dump(self):
        original = self._make_dependency(
            purl="pkg:pypi/requests@2.31.0",
            type="pypi",
            direct=True,
            locations=["/app/requirements.txt"],
        )
        dumped = original.model_dump(by_alias=True)
        restored = Dependency(**dumped)
        assert restored.id == original.id
        assert restored.name == "requests"
        assert restored.purl == "pkg:pypi/requests@2.31.0"
        assert restored.direct is True
        assert restored.locations == ["/app/requirements.txt"]

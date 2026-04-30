"""Tests for the /api/v1/scripts endpoints (versioned scanner serving).

Covers: whitelist + path-traversal rejection, ?v= regex (Unicode digits,
extra segments, empty), 404 for unknown versions, hash + content
endpoints for the latest pointer and frozen releases, manifest
enumeration, and the lru_cache used for frozen reads.
"""

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.api.v1.endpoints import scripts as scripts_module


MODULE = "app.api.v1.endpoints.scripts"

LATEST_CONTENT = '#!/usr/bin/env bash\nSCRIPT_VERSION="1.1.0"\n# latest body\n'
V_1_0_0_CONTENT = '#!/usr/bin/env bash\nSCRIPT_VERSION="1.0.0"\n# frozen 1.0.0\n'
V_1_1_0_CONTENT = '#!/usr/bin/env bash\nSCRIPT_VERSION="1.1.0"\n# frozen 1.1.0\n'


@pytest.fixture
def scripts_layout(tmp_path: Path):
    """Build a temp scripts/ + versions/ directory and patch the module
    constants so handlers operate on it for the duration of the test."""
    scripts_dir = tmp_path / "scripts"
    versions_dir = scripts_dir / "versions"
    versions_dir.mkdir(parents=True)
    (scripts_dir / "scanner.sh").write_text(LATEST_CONTENT)
    (versions_dir / "scanner-1.0.0.sh").write_text(V_1_0_0_CONTENT)
    (versions_dir / "scanner-1.1.0.sh").write_text(V_1_1_0_CONTENT)
    # The lru_cache memoises by absolute path string; clear it so prior
    # test runs (or other fixtures) don't leak cached bytes.
    scripts_module._read_and_describe_frozen.cache_clear()
    with (
        patch.object(scripts_module, "SCRIPTS_DIR", scripts_dir),
        patch.object(scripts_module, "VERSIONS_DIR", versions_dir),
    ):
        yield scripts_dir
    scripts_module._read_and_describe_frozen.cache_clear()


class TestValidateScriptName:
    def test_rejects_unknown_script(self, scripts_layout):
        with pytest.raises(HTTPException) as exc:
            scripts_module.validate_script_name("evil.sh")
        assert exc.value.status_code == 404

    def test_accepts_whitelisted(self, scripts_layout):
        scripts_module.validate_script_name("scanner.sh")  # no raise


class TestVersionRegex:
    @pytest.mark.parametrize(
        "good",
        ["1.0.0", "1.1.0", "10.20.30", "0.0.0"],
    )
    def test_accepts_semver_shape(self, good):
        assert scripts_module._VERSION_RE.fullmatch(good)

    @pytest.mark.parametrize(
        "bad",
        [
            "1.0",          # too few segments
            "1.0.0.0",      # too many segments
            "1.0.0-rc1",    # suffixes not allowed
            "../../etc",
            "..",
            "",
            "1.0.x",
            "v1.0.0",
            "٠.٠.٠",  # Arabic-Indic digits — must NOT match under re.ASCII
        ],
    )
    def test_rejects_non_semver(self, bad):
        assert scripts_module._VERSION_RE.fullmatch(bad) is None


class TestResolveScriptPath:
    def test_no_version_returns_latest_pointer(self, scripts_layout):
        path = scripts_module._resolve_script_path("scanner.sh", None)
        assert path == (scripts_layout / "scanner.sh").resolve()

    def test_with_version_returns_frozen_path(self, scripts_layout):
        path = scripts_module._resolve_script_path("scanner.sh", "1.0.0")
        assert path == (scripts_layout / "versions" / "scanner-1.0.0.sh").resolve()

    def test_invalid_version_raises_400(self, scripts_layout):
        with pytest.raises(HTTPException) as exc:
            scripts_module._resolve_script_path("scanner.sh", "../../etc")
        assert exc.value.status_code == 400


class TestGetScriptContent:
    def test_latest_pointer(self, scripts_layout):
        content, version, sha = scripts_module.get_script_content("scanner.sh")
        assert content == LATEST_CONTENT
        assert version == "1.1.0"
        assert len(sha) == 64

    def test_pinned_v_1_0_0(self, scripts_layout):
        content, version, _ = scripts_module.get_script_content("scanner.sh", version="1.0.0")
        assert content == V_1_0_0_CONTENT
        assert version == "1.0.0"

    def test_unknown_version_raises_filenotfound(self, scripts_layout):
        with pytest.raises(FileNotFoundError):
            scripts_module.get_script_content("scanner.sh", version="9.9.9")


class TestPrefixCollisionImmunity:
    """Regression: an attacker-controlled sibling like
    /tmp/.../scripts/versions-evil/scanner-1.0.0.sh must not be served
    when the base is /tmp/.../scripts/versions. The check uses
    Path.is_relative_to instead of str.startswith, which used to allow
    the sibling through."""

    def test_sibling_directory_not_served(self, tmp_path: Path):
        scripts_dir = tmp_path / "scripts"
        versions_dir = scripts_dir / "versions"
        evil_dir = scripts_dir / "versions-evil"
        versions_dir.mkdir(parents=True)
        evil_dir.mkdir(parents=True)
        (scripts_dir / "scanner.sh").write_text(LATEST_CONTENT)
        (evil_dir / "scanner-1.0.0.sh").write_text("#!/bin/sh\n# attacker payload\n")

        scripts_module._read_and_describe_frozen.cache_clear()
        with (
            patch.object(scripts_module, "SCRIPTS_DIR", scripts_dir),
            patch.object(scripts_module, "VERSIONS_DIR", versions_dir),
        ):
            # The legitimate versions/ dir has no scanner-1.0.0.sh so the
            # request must 404 — never resolve into versions-evil/.
            with pytest.raises(FileNotFoundError):
                scripts_module.get_script_content("scanner.sh", version="1.0.0")
        scripts_module._read_and_describe_frozen.cache_clear()


class TestListAvailableVersions:
    def test_lists_frozen_versions_sorted(self, scripts_layout):
        out = scripts_module.list_available_versions("scanner.sh")
        assert out == ["1.0.0", "1.1.0"]

    def test_natural_sort(self, tmp_path: Path):
        versions_dir = tmp_path / "versions"
        versions_dir.mkdir()
        for v in ["1.0.0", "1.0.10", "1.0.2", "1.10.0", "2.0.0"]:
            (versions_dir / f"scanner-{v}.sh").write_text(f'SCRIPT_VERSION="{v}"\n')
        with patch.object(scripts_module, "VERSIONS_DIR", versions_dir):
            out = scripts_module.list_available_versions("scanner.sh")
        assert out == ["1.0.0", "1.0.2", "1.0.10", "1.10.0", "2.0.0"]


class TestFrozenCacheBehaviour:
    """The lru_cache around _read_and_describe_frozen treats released
    bytes as immutable for the process lifetime. Latest-pointer reads
    must not be cached."""

    def test_frozen_read_is_cached(self, scripts_layout):
        scripts_module._read_and_describe_frozen.cache_clear()
        scripts_module.get_script_content("scanner.sh", version="1.0.0")
        scripts_module.get_script_content("scanner.sh", version="1.0.0")
        info = scripts_module._read_and_describe_frozen.cache_info()
        assert info.hits == 1
        assert info.misses == 1

    def test_latest_pointer_is_not_cached(self, scripts_layout):
        scripts_module._read_and_describe_frozen.cache_clear()
        scripts_module.get_script_content("scanner.sh")
        scripts_module.get_script_content("scanner.sh")
        info = scripts_module._read_and_describe_frozen.cache_info()
        assert info.hits == 0
        assert info.misses == 0


class TestHandlers:
    def test_get_script_hash_pinned(self, scripts_layout):
        info = asyncio.run(scripts_module.get_script_hash("scanner.sh", v="1.0.0"))
        assert info.version == "1.0.0"
        assert info.url.endswith("?v=1.0.0")
        assert len(info.sha256) == 64

    def test_get_script_hash_invalid_version_raises_400(self, scripts_layout):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(scripts_module.get_script_hash("scanner.sh", v="٠.٠.٠"))
        assert exc.value.status_code == 400

    def test_get_script_unknown_version_raises_404(self, scripts_layout):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(scripts_module.get_script("scanner.sh", v="9.9.9"))
        assert exc.value.status_code == 404

    def test_list_scripts_enumerates_latest_plus_frozen(self, scripts_layout):
        manifest = asyncio.run(scripts_module.list_scripts())
        urls = [s.url for s in manifest.scripts]
        assert "/api/v1/scripts/scanner.sh" in urls
        assert "/api/v1/scripts/scanner.sh?v=1.0.0" in urls
        assert "/api/v1/scripts/scanner.sh?v=1.1.0" in urls

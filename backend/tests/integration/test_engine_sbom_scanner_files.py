"""The engine loads one stored SBOM at a time and hands trivy and grype one temp file of the stored bytes; a timed-out
scanner runs once and fails the scan's coverage."""

import asyncio
import hashlib
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.constants import SCAN_STATUS_COMPLETED, SCAN_STATUS_COMPLETED_WITH_ERRORS
from app.core.init_db import create_indexes
from app.models.project import Scan
from app.services.analysis import engine
from app.services.analyzers.trivy import TrivyAnalyzer
from tests.helpers.sboms import store_sbom

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"
_PROJECT_ID = "scanner-files-project"
_WORKER = "pod-a/worker-0"
_SCANNERS = ["grype", "trivy"]

# Logs "<scanner> <sha256> <path>" for the SBOM file among its arguments, then reports no findings.
_FAKE_SCANNER = """#!/bin/sh
for arg in "$@"; do candidate="${arg#sbom:}"; [ -f "$candidate" ] && path="$candidate"; done
if command -v sha256sum >/dev/null; then digest=$(sha256sum "$path"); else digest=$(shasum -a 256 "$path"); fi
echo "$(basename "$0") ${digest%% *} $path" >> "$SCANNER_LOG"
echo '{}'
"""
# Writes syft's own CycloneDX rendering of the same project to the -o target.
_FAKE_SYFT = """#!/bin/sh
case "$4" in cyclonedx-json=*) cp "$CONVERTED_FIXTURE" "${4#cyclonedx-json=}";; *) exit 1;; esac
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _append(path: Path, line: str) -> None:
    with path.open("a") as log:
        log.write(line + "\n")


@pytest.fixture
def scanners(tmp_path, monkeypatch) -> SimpleNamespace:
    bin_dir, tmp_dir, log = tmp_path / "bin", tmp_path / "tmp", tmp_path / "scanner.log"
    bin_dir.mkdir()
    tmp_dir.mkdir()
    for name, script in (("trivy", _FAKE_SCANNER), ("grype", _FAKE_SCANNER), ("syft", _FAKE_SYFT)):
        (bin_dir / name).write_text(script)
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("SCANNER_LOG", str(log))
    monkeypatch.setenv("CONVERTED_FIXTURE", str(_FIXTURES / "uvdev.syft.cdx.json"))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_dir))

    real_bucket = engine.AsyncIOMotorGridFSBucket

    def recording_bucket(db):
        fs = real_bucket(db)
        open_stream = fs.open_download_stream

        async def logged(file_id, *args, **kwargs):
            await asyncio.to_thread(_append, log, f"download {file_id}")
            return await open_stream(file_id, *args, **kwargs)

        fs.open_download_stream = logged
        return fs

    monkeypatch.setattr(engine, "AsyncIOMotorGridFSBucket", recording_bucket)
    return SimpleNamespace(log=log, tmp_dir=tmp_dir, bin_dir=bin_dir)


async def _stored_scan(db, *sboms: bytes) -> tuple[str, list[dict]]:
    refs = [await store_sbom(db, data) for data in sboms]
    scan = Scan(project_id=_PROJECT_ID, branch="main", sbom_refs=refs, status="processing", worker_id=_WORKER)
    await db.scans.insert_one(scan.model_dump(by_alias=True))
    return scan.id, refs


async def _events(scanners: SimpleNamespace) -> list[list[str]]:
    return [line.split(" ") for line in (await asyncio.to_thread(scanners.log.read_text)).splitlines()]


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_each_sbom_is_scanned_from_one_file_of_its_stored_bytes_before_the_next_one_loads(db, scanners):
    stored = [
        await asyncio.to_thread((_FIXTURES / name).read_bytes)
        for name in ("uvdev.syft.cdx.json", "cargo.trivy.cdx.json")
    ]
    scan_id, refs = await _stored_scan(db, *stored)

    assert await engine.run_analysis(scan_id, refs, _SCANNERS, db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    events = await _events(scanners)
    assert [event[0] for event in events[::3]] == ["download", "download"]
    for position, (ref, data) in enumerate(zip(refs, stored, strict=True)):
        download, *scans = events[position * 3 : position * 3 + 3]
        assert download == ["download", ref["gridfs_id"]]
        assert sorted(scanner for scanner, _, _ in scans) == _SCANNERS
        assert {(digest, path) for _, digest, path in scans} == {(_sha(data), scans[0][2])}
        assert Path(scans[0][2]).parent == scanners.tmp_dir
        assert Path(scans[0][2]).name.startswith("dc-sbom-")
    assert list(scanners.tmp_dir.glob("dc-sbom-*")) == []


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_syft_json_sbom_reaches_trivy_converted_and_grype_as_stored(db, scanners):
    stored = await asyncio.to_thread((_FIXTURES / "uvdev.syft.json").read_bytes)
    converted = await asyncio.to_thread((_FIXTURES / "uvdev.syft.cdx.json").read_bytes)
    scan_id, refs = await _stored_scan(db, stored)

    assert await engine.run_analysis(scan_id, refs, _SCANNERS, db, worker_id=_WORKER) == SCAN_STATUS_COMPLETED

    download, *scans = await _events(scanners)
    assert download == ["download", refs[0]["gridfs_id"]]
    by_scanner = {scanner: (digest, path) for scanner, digest, path in scans}
    grype_path = by_scanner["grype"][1]
    assert by_scanner["grype"] == (_sha(stored), grype_path)
    assert by_scanner["trivy"] == (_sha(converted), f"{grype_path}.cdx.json")
    assert list(scanners.tmp_dir.iterdir()) == []


# Trivy's own 5m deadline matches the default cli_timeout and ends it with a retryable error; this stand-in's
# deadline fires first unless --timeout moves it past cli_timeout.
_HANGING_TRIVY = """#!/bin/sh
echo trivy >> "$SCANNER_LOG"
case " $* " in *" --timeout "*) exec sleep 400;; esac
sleep 0.5
echo "context deadline exceeded" >&2
exit 1
"""


@pytest.mark.live_mongo
@pytest.mark.asyncio
async def test_a_trivy_that_outlives_cli_timeout_runs_once_and_the_scan_names_it_failed(db, scanners, monkeypatch):
    await asyncio.to_thread((scanners.bin_dir / "trivy").write_text, _HANGING_TRIVY)
    monkeypatch.setattr(TrivyAnalyzer, "cli_timeout", 1)
    await create_indexes(db)
    stored = await asyncio.to_thread((_FIXTURES / "cargo.trivy.cdx.json").read_bytes)
    scan_id, refs = await _stored_scan(db, stored)

    status = await engine.run_analysis(scan_id, refs, ["trivy"], db, worker_id=_WORKER)

    assert status == SCAN_STATUS_COMPLETED_WITH_ERRORS
    assert await _events(scanners) == [["download", refs[0]["gridfs_id"]], ["trivy"]]
    assert (await db.scans.find_one({"_id": scan_id}))["failed_analyzers"] == ["trivy"]

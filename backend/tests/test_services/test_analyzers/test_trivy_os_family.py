import asyncio
import json
import threading
from pathlib import Path

import pytest

from app.schemas.sbom import SBOMFormat
from app.services.analyzers import trivy
from app.services.analyzers.trivy import TrivyAnalyzer

_RHEL_OS = {
    "bom-ref": "os:rhel@9.7",
    "type": "operating-system",
    "name": "rhel",
    "version": "9.7",
    "swid": {"tagId": "rhel", "name": "rhel", "version": "9.7"},
}
_REDHAT_OS = {**_RHEL_OS, "name": "redhat"}
_UBUNTU_OS = {"bom-ref": "os:ubuntu@24.04", "type": "operating-system", "name": "ubuntu", "version": "24.04"}
_PACKAGE_NAMED_RHEL = {
    "bom-ref": "pkg:rpm/redhat/rhel@9.7",
    "type": "library",
    "name": "rhel",
    "version": "9.7",
    "purl": "pkg:rpm/redhat/rhel@9.7?distro=rhel-9.7",
}


def _cyclonedx(*components: dict) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)}


async def _post(tmp_path: Path, text: str) -> Path:
    posted = tmp_path / "dc-sbom-posted.json"
    await asyncio.to_thread(posted.write_text, text)
    return posted


async def _read_json(path: str) -> dict:
    return json.loads(await asyncio.to_thread(Path(path).read_text))


def _created_besides(tmp_path: Path, posted: Path) -> list[str]:
    return sorted(str(path) for path in tmp_path.iterdir() if path != posted)


@pytest.fixture
def syft_runs(monkeypatch) -> list[list[str]]:
    runs: list[list[str]] = []

    async def unexpected_syft(args, _time_limit):
        runs.append(args)
        return b"", b"", 1

    monkeypatch.setattr(trivy, "run_process", unexpected_syft)
    return runs


@pytest.mark.asyncio
async def test_trivy_scans_a_copy_that_names_the_rhel_operating_system_redhat(tmp_path, syft_runs):
    posted_text = json.dumps(_cyclonedx(_RHEL_OS, _PACKAGE_NAMED_RHEL))
    posted = await _post(tmp_path, posted_text)

    target, extra = await TrivyAnalyzer()._preprocess_sbom(str(posted), SBOMFormat.CYCLONEDX)

    assert await asyncio.to_thread(posted.read_text) == posted_text
    assert extra == [target] == _created_besides(tmp_path, posted)
    assert await _read_json(target) == _cyclonedx(_REDHAT_OS, _PACKAGE_NAMED_RHEL)
    assert syft_runs == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sbom_format", "posted_text"),
    [
        (SBOMFormat.CYCLONEDX, json.dumps(_cyclonedx(_UBUNTU_OS, _PACKAGE_NAMED_RHEL))),
        (SBOMFormat.CYCLONEDX, json.dumps(_cyclonedx(_PACKAGE_NAMED_RHEL))),
        (SBOMFormat.CYCLONEDX, json.dumps(_cyclonedx(_RHEL_OS))[:-3]),
        (
            SBOMFormat.SPDX,
            json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-os", "name": "rhel"}]}),
        ),
    ],
    ids=["cyclonedx-ubuntu", "cyclonedx-without-os", "cyclonedx-unparsable", "spdx"],
)
async def test_trivy_reads_the_posted_file_when_there_is_no_rhel_operating_system_to_rename(
    tmp_path, syft_runs, sbom_format, posted_text
):
    posted = await _post(tmp_path, posted_text)

    target, extra = await TrivyAnalyzer()._preprocess_sbom(str(posted), sbom_format)

    assert (target, extra, syft_runs) == (str(posted), [], [])
    assert _created_besides(tmp_path, posted) == []
    assert await asyncio.to_thread(posted.read_text) == posted_text


@pytest.mark.asyncio
async def test_a_syft_converted_rhel_sbom_reaches_trivy_with_its_operating_system_named_redhat(monkeypatch, tmp_path):
    posted = tmp_path / "dc-sbom-posted.json"
    converted_text = json.dumps(_cyclonedx(_RHEL_OS, _PACKAGE_NAMED_RHEL))

    async def syft_convert(args, _time_limit):
        converted = Path(args[-1].removeprefix("cyclonedx-json="))
        await asyncio.to_thread(converted.write_text, converted_text)
        return b"", b"", 0

    monkeypatch.setattr(trivy, "run_process", syft_convert)

    target, extra = await TrivyAnalyzer()._preprocess_sbom(str(posted), SBOMFormat.SYFT)

    assert target in extra
    assert sorted(extra) == _created_besides(tmp_path, posted)
    assert await _read_json(target) == _cyclonedx(_REDHAT_OS, _PACKAGE_NAMED_RHEL)
    assert [await asyncio.to_thread(Path(path).read_text) for path in extra if path != target] == [converted_text]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sbom_format", "posted_text"),
    [
        (
            SBOMFormat.CYCLONEDX,
            json.dumps(
                _cyclonedx(
                    {
                        **_UBUNTU_OS,
                        "name": "rocky",
                        "properties": [{"name": "syft:distro:idLike:0", "value": "rhel"}],
                    }
                )
            ),
        ),
        (
            SBOMFormat.SPDX,
            json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"SPDXID": "SPDXRef-os", "name": "rhel"}]}),
        ),
    ],
    ids=["cyclonedx-rhel-only-as-id-like", "spdx"],
)
async def test_trivy_parses_no_sbom_that_cannot_name_a_rhel_operating_system(
    monkeypatch, tmp_path, syft_runs, sbom_format, posted_text
):
    def unexpected_parse(*_args, **_kwargs):
        raise AssertionError("parsed an SBOM that names no rhel operating system")

    monkeypatch.setattr(trivy.json, "loads", unexpected_parse)
    posted = await _post(tmp_path, posted_text)

    target, extra = await TrivyAnalyzer()._preprocess_sbom(str(posted), sbom_format)

    assert (target, extra, syft_runs) == (str(posted), [], [])
    assert _created_besides(tmp_path, posted) == []


@pytest.mark.asyncio
async def test_malformed_component_entries_do_not_stop_the_rename(tmp_path, syft_runs):
    posted = await _post(tmp_path, json.dumps(_cyclonedx(None, "rhel", _RHEL_OS)))

    target, extra = await TrivyAnalyzer()._preprocess_sbom(str(posted), SBOMFormat.CYCLONEDX)

    assert extra == [target]
    assert await _read_json(target) == _cyclonedx(None, "rhel", _REDHAT_OS)


@pytest.mark.asyncio
async def test_a_failed_copy_leaves_no_file_behind_and_trivy_reads_the_posted_file(monkeypatch, tmp_path, syft_runs):
    def disk_full(_document, file, **_kwargs):
        file.write('{"bomFormat": "Cyclo')
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(trivy.json, "dump", disk_full)
    posted = await _post(tmp_path, json.dumps(_cyclonedx(_RHEL_OS)))

    target, extra = await TrivyAnalyzer()._preprocess_sbom(str(posted), SBOMFormat.CYCLONEDX)

    assert (target, extra) == (str(posted), [])
    assert _created_besides(tmp_path, posted) == []


@pytest.mark.asyncio
async def test_the_copy_is_made_off_the_event_loop(monkeypatch, tmp_path, syft_runs):
    loop_thread = threading.get_ident()
    copy_threads: list[int] = []
    name_rhel_redhat = trivy._name_rhel_redhat

    def recording(source: str, target: str) -> bool:
        copy_threads.append(threading.get_ident())
        return name_rhel_redhat(source, target)

    monkeypatch.setattr(trivy, "_name_rhel_redhat", recording)
    posted = await _post(tmp_path, json.dumps(_cyclonedx(_RHEL_OS)))

    await TrivyAnalyzer()._preprocess_sbom(str(posted), SBOMFormat.CYCLONEDX)

    assert copy_threads and loop_thread not in copy_threads

"""cli_timeout is awaited inside the analyzer's coroutine, so cancelling the run cancels the ceiling with it."""

import asyncio
import json
import threading
from pathlib import Path

import pytest

from app.schemas.sbom import SBOMFormat
from app.services.analyzers.grype import GrypeAnalyzer
from app.services.analyzers.trivy import TrivyAnalyzer

# Stands in for an unfinished scanner: the real binaries are absent and the assertion is about lifetime.
_HANGING_SCANNER = ["sleep", "400"]
_SCALED_TIMEOUT = 0.3
_CANCEL_AFTER_SECONDS = 0.3
_ONE_PROCESS = 1
_TOOL_FAILED = 1
_NO_STDOUT = b""
_TEMP_SBOM_PATH = "/tmp/adhoc-sbom.json"
# A syft that did not finish may still have left a partial file here.
_CONVERTED_PATH = f"{_TEMP_SBOM_PATH}.cdx.json"
_CONVERTED_SBOM = '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}'
_FAILING_CONVERTER = ["sh", "-c", "echo 'unknown SBOM format' >&2; exit 1"]


def _record_and_hang(monkeypatch: pytest.MonkeyPatch, spawned: list, stand_in: list[str] = _HANGING_SCANNER) -> None:
    start_process = asyncio.create_subprocess_exec

    async def _stand_in(*_args, **kwargs):
        process = await start_process(*stand_in, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _stand_in)


@pytest.mark.asyncio
async def test_a_cancelled_run_kills_the_scanner_it_started(monkeypatch):
    spawned: list = []
    _record_and_hang(monkeypatch, spawned)

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(GrypeAnalyzer()._execute_command(_HANGING_SCANNER), timeout=_CANCEL_AFTER_SECONDS)

    assert len(spawned) == _ONE_PROCESS
    assert spawned[0].returncode is not None, "the scanner outlived the run that started it"


@pytest.mark.asyncio
async def test_the_tools_own_timeout_still_ends_the_scanner_when_nothing_cancels(monkeypatch):
    """The ceiling that already worked has to keep working: it is the only one on the scan path."""
    spawned: list = []
    _record_and_hang(monkeypatch, spawned)
    analyzer = GrypeAnalyzer()
    monkeypatch.setattr(analyzer, "cli_timeout", _SCALED_TIMEOUT)

    stdout, stderr, returncode = await analyzer._execute_command(_HANGING_SCANNER)

    assert (stdout, returncode) == (_NO_STDOUT, _TOOL_FAILED)
    assert b"timed out" in stderr
    assert spawned[0].returncode is not None


@pytest.mark.asyncio
async def test_a_syft_conversion_that_never_finishes_is_bounded_and_the_scan_goes_on(monkeypatch):
    """Trivy reads the posted format well enough to continue, so a stuck converter is abandoned, not waited out."""
    spawned: list = []
    _record_and_hang(monkeypatch, spawned)
    analyzer = TrivyAnalyzer()
    monkeypatch.setattr(analyzer, "syft_convert_timeout", _SCALED_TIMEOUT)

    target, extra = await analyzer._preprocess_sbom(_TEMP_SBOM_PATH, SBOMFormat.SYFT)

    assert (target, extra) == (_TEMP_SBOM_PATH, [_CONVERTED_PATH])
    assert spawned[0].returncode is not None, "the converter outlived its own ceiling"


@pytest.mark.asyncio
async def test_a_cancelled_run_kills_the_syft_conversion_too(monkeypatch):
    spawned: list = []
    _record_and_hang(monkeypatch, spawned)
    coroutine = TrivyAnalyzer()._preprocess_sbom(_TEMP_SBOM_PATH, SBOMFormat.SYFT)

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(coroutine, timeout=_CANCEL_AFTER_SECONDS)

    assert len(spawned) == _ONE_PROCESS
    assert spawned[0].returncode is not None, "the converter outlived the run that started it"


@pytest.mark.asyncio
async def test_a_finished_syft_conversion_hands_trivy_the_converted_file(monkeypatch, tmp_path):
    posted = str(tmp_path / "sbom.json")
    _record_and_hang(monkeypatch, [], ["sh", "-c", f"printf '%s' '{_CONVERTED_SBOM}' > '{posted}.cdx.json'"])

    target, extra = await TrivyAnalyzer()._preprocess_sbom(posted, SBOMFormat.SYFT)

    assert extra == [target] == [f"{posted}.cdx.json"]
    assert await asyncio.to_thread(Path(target).read_text) == _CONVERTED_SBOM


@pytest.mark.asyncio
async def test_a_failed_syft_conversion_leaves_trivy_the_posted_file(monkeypatch):
    _record_and_hang(monkeypatch, [], _FAILING_CONVERTER)

    target, extra = await TrivyAnalyzer()._preprocess_sbom(_TEMP_SBOM_PATH, SBOMFormat.SYFT)

    assert (target, extra) == (_TEMP_SBOM_PATH, [_CONVERTED_PATH])


@pytest.mark.asyncio
@pytest.mark.parametrize("sbom_format", [SBOMFormat.CYCLONEDX, SBOMFormat.SPDX])
async def test_trivy_reads_cyclonedx_and_spdx_as_posted(monkeypatch, sbom_format):
    spawned: list = []
    _record_and_hang(monkeypatch, spawned)

    target, extra = await TrivyAnalyzer()._preprocess_sbom(_TEMP_SBOM_PATH, sbom_format)

    assert (target, extra, spawned) == (_TEMP_SBOM_PATH, [], [])


_GRYPE_OUTPUT = Path(__file__).parents[2] / "fixtures" / "grype" / "grype_0.119_matches.json"
_UV_SBOM = Path(__file__).parents[2] / "fixtures" / "sbom" / "uvdev.syft.cdx.json"


@pytest.mark.asyncio
async def test_the_temp_sbom_and_the_scanner_output_are_handled_off_the_event_loop(monkeypatch):
    analyzer = GrypeAnalyzer()
    threads: dict[str, int] = {}
    stdout = await asyncio.to_thread(_GRYPE_OUTPUT.read_bytes)

    def recorded(step):
        original = getattr(analyzer, step)

        def run(*args):
            threads[step] = threading.get_ident()
            return original(*args)

        return run

    scanned: list[str] = []

    async def scanner_output(args):
        scanned.append(args[1].removeprefix("sbom:"))
        return stdout, b"", 0

    for step in ("_create_temp_sbom", "_parse_output"):
        monkeypatch.setattr(analyzer, step, recorded(step))
    monkeypatch.setattr(analyzer, "is_tool_available", lambda: True)
    monkeypatch.setattr(analyzer, "_execute_command", scanner_output)
    sbom = json.loads(await asyncio.to_thread(_UV_SBOM.read_text))

    result = await analyzer.analyze(sbom, parsed_components=[])

    assert [match["artifact"]["name"] for match in result["matches"]] == ["brace-expansion", "libgnutls30", "libc-bin"]
    assert sorted(threads) == ["_create_temp_sbom", "_parse_output"]
    assert threading.get_ident() not in threads.values()
    assert Path(scanned[0]).name.startswith("dc-sbom-")
    assert not await asyncio.to_thread(Path(scanned[0]).exists)

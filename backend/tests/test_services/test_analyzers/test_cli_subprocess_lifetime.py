"""No CLI scanner outlives the run that started it.

``cli_timeout`` is awaited inside the analyzer's own coroutine, so a caller that cancels the run —
the ad-hoc deadline, a worker shutdown — cancels the ceiling along with it and leaves the scanner
bounded only by the tool deciding to exit. Both analyzers that fork are covered: the shared
``_execute_command`` every CLI analyzer runs through, and Trivy's syft conversion beside it.
"""

import asyncio
import json
import threading
from pathlib import Path

import pytest

from app.services.analyzers.grype import GrypeAnalyzer
from app.services.analyzers.trivy import TrivyAnalyzer

# Stands in for a scanner that has not finished yet: the real binaries are absent here and the
# image's are not reproducible, and what these assert is the lifetime, not the output.
_HANGING_SCANNER = ["sleep", "400"]
_SCALED_TIMEOUT = 0.3
_CANCEL_AFTER_SECONDS = 0.3
_ONE_PROCESS = 1
_TOOL_FAILED = 1
_NO_STDOUT = b""
_NO_EXTRA_FILES: list[str] = []
_TEMP_SBOM_PATH = "/tmp/adhoc-sbom.json"
# Neither CycloneDX nor SPDX, so Trivy reaches for syft to convert it.
_SYFT_JSON_SBOM = {"artifacts": [], "descriptor": {"name": "syft"}}
_CONVERTED_SBOM = '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}'
_FAILING_CONVERTER = ["sh", "-c", "echo 'unknown SBOM format' >&2; exit 1"]


def _record_and_hang(monkeypatch: pytest.MonkeyPatch, spawned: list, stand_in: list[str] = _HANGING_SCANNER) -> None:
    """Every subprocess the analyzer starts becomes the stand-in, hanging by default, and is handed back."""
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
    """Trivy reads the posted format well enough to continue, so a stuck converter is worth
    abandoning rather than waiting out."""
    spawned: list = []
    _record_and_hang(monkeypatch, spawned)
    analyzer = TrivyAnalyzer()
    monkeypatch.setattr(analyzer, "syft_convert_timeout", _SCALED_TIMEOUT)

    target, extra = await analyzer._preprocess_sbom(_SYFT_JSON_SBOM, _TEMP_SBOM_PATH)

    assert (target, extra) == (_TEMP_SBOM_PATH, _NO_EXTRA_FILES)
    assert spawned[0].returncode is not None, "the converter outlived its own ceiling"


@pytest.mark.asyncio
async def test_a_cancelled_run_kills_the_syft_conversion_too(monkeypatch):
    spawned: list = []
    _record_and_hang(monkeypatch, spawned)
    coroutine = TrivyAnalyzer()._preprocess_sbom(_SYFT_JSON_SBOM, _TEMP_SBOM_PATH)

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(coroutine, timeout=_CANCEL_AFTER_SECONDS)

    assert len(spawned) == _ONE_PROCESS
    assert spawned[0].returncode is not None, "the converter outlived the run that started it"


@pytest.mark.asyncio
async def test_a_finished_syft_conversion_hands_trivy_the_converted_file(monkeypatch, tmp_path):
    _record_and_hang(monkeypatch, [], ["printf", "%s", _CONVERTED_SBOM])
    posted = str(tmp_path / "sbom.json")

    target, extra = await TrivyAnalyzer()._preprocess_sbom(_SYFT_JSON_SBOM, posted)

    assert extra == [target] == [f"{posted}.cdx.json"]
    assert await asyncio.to_thread(Path(target).read_text) == _CONVERTED_SBOM


@pytest.mark.asyncio
async def test_a_failed_syft_conversion_leaves_trivy_the_posted_file(monkeypatch):
    _record_and_hang(monkeypatch, [], _FAILING_CONVERTER)

    target, extra = await TrivyAnalyzer()._preprocess_sbom(_SYFT_JSON_SBOM, _TEMP_SBOM_PATH)

    assert (target, extra) == (_TEMP_SBOM_PATH, _NO_EXTRA_FILES)


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

    async def scanner_output(_args):
        return stdout, b"", 0

    for step in ("_create_temp_sbom", "_parse_output"):
        monkeypatch.setattr(analyzer, step, recorded(step))
    monkeypatch.setattr(analyzer, "is_tool_available", lambda: True)
    monkeypatch.setattr(analyzer, "_execute_command", scanner_output)
    sbom = json.loads(await asyncio.to_thread(_UV_SBOM.read_text))

    result = await analyzer.analyze(sbom)

    assert [match["artifact"]["name"] for match in result["matches"]] == ["brace-expansion", "libgnutls30", "libc-bin"]
    assert sorted(threads) == ["_create_temp_sbom", "_parse_output"]
    assert threading.get_ident() not in threads.values()

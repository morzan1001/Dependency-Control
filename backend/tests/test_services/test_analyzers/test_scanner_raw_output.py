"""Trivy results are stored as the scanner wrote them; Grype's keep only the match keys normalize_grype reads."""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest

from app.services.analyzers.grype import GrypeAnalyzer
from app.services.analyzers.trivy import TrivyAnalyzer


def test_the_stored_trivy_result_is_the_parsed_scanner_output():
    raw = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "UNKNOWN"}]}]}
    assert TrivyAnalyzer()._parse_output(json.dumps(raw).encode()) == raw


@pytest.mark.parametrize("analyzer", [TrivyAnalyzer(), GrypeAnalyzer()])
def test_empty_output_is_an_empty_result(analyzer):
    assert analyzer._parse_output(b"  ") == {analyzer.empty_result_key: []}


_FIXTURES = Path(__file__).parents[2] / "fixtures"
# Records the file grype was pointed at, then prints what grype 0.119 printed for a real SBOM.
_FAKE_GRYPE = """#!/bin/sh
echo "${1#sbom:}" > "$SCANNED_LOG"
cat "$GRYPE_OUTPUT"
"""


@pytest.mark.asyncio
async def test_an_adhoc_grype_run_reads_a_temp_copy_of_the_document_and_removes_it(tmp_path, monkeypatch):
    bin_dir, tmp_dir, scanned_log = tmp_path / "bin", tmp_path / "tmp", tmp_path / "scanned"
    bin_dir.mkdir()
    tmp_dir.mkdir()
    (bin_dir / "grype").write_text(_FAKE_GRYPE)
    (bin_dir / "grype").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("SCANNED_LOG", str(scanned_log))
    monkeypatch.setenv("GRYPE_OUTPUT", str(_FIXTURES / "grype" / "grype_0.119_matches.json"))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_dir))
    sbom = json.loads(await asyncio.to_thread((_FIXTURES / "sbom" / "uvdev.syft.cdx.json").read_text))

    result = await GrypeAnalyzer().analyze(sbom)

    assert [match["artifact"]["name"] for match in result["matches"]] == ["brace-expansion", "libgnutls30", "libc-bin"]
    assert Path((await asyncio.to_thread(scanned_log.read_text)).strip()).name.startswith("dc-sbom-")
    assert list(tmp_dir.iterdir()) == []

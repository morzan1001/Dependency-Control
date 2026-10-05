"""The findings CSV names every CVE of a vulnerability finding, read through the export's own projection."""

import csv
import io

import pytest

from app.services.analysis.engine import _prepare_finding_records
from app.services.inventory.csv_stream import iter_csv
from app.services.inventory.findings_export import FINDINGS_COLUMNS, ExportedScan, iter_findings_rows
from tests.helpers.findings import grype_findings

pytestmark = [pytest.mark.asyncio, pytest.mark.live_mongo]

_SCAN = ExportedScan("s-export", "main", None, None)


async def test_a_vulnerability_row_carries_its_cves_and_a_title(db):
    # The fixture's own advisory is GHSA-v6h2-p8h4-qcjw, which grype relates to CVE-2025-5889.
    findings = grype_findings([("lodash", "4.17.20", None), ("lodash", "4.17.20", "CVE-2021-23337")])
    records, _ = _prepare_finding_records(findings, _SCAN.id, "p-export", None)
    await db.findings.insert_many(records)

    text = "".join([chunk async for chunk in iter_csv(FINDINGS_COLUMNS, iter_findings_rows(db, [_SCAN]))])
    [row] = csv.DictReader(io.StringIO(text.lstrip("﻿")))

    assert (row["finding_id"], row["title"], row.get("cves")) == (
        "lodash:4.17.20",
        "CVE-2021-23337",
        "CVE-2021-23337; CVE-2025-5889",
    )

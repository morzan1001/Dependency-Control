"""Tests for the streaming CSV renderer shared by all inventory/export views."""

import csv
import io

import pytest

from app.services.inventory.csv_stream import export_filename, format_cell, iter_csv


async def _rows(items):
    for item in items:
        yield item


async def _collect(columns, items) -> str:
    chunks = [chunk async for chunk in iter_csv(columns, _rows(items))]
    return "".join(chunks)


@pytest.mark.asyncio
async def test_first_chunk_starts_with_bom_and_header():
    out = await _collect(["a", "b"], [])
    assert out.startswith("﻿")
    reader = csv.reader(io.StringIO(out.lstrip("﻿")))
    assert next(reader) == ["a", "b"]


@pytest.mark.asyncio
async def test_rows_follow_column_order_and_missing_keys_are_empty():
    out = await _collect(["a", "b", "c"], [{"b": "2", "a": "1"}])
    reader = csv.reader(io.StringIO(out.lstrip("﻿")))
    next(reader)
    assert next(reader) == ["1", "2", ""]


@pytest.mark.asyncio
async def test_umlauts_and_commas_survive_quoting():
    out = await _collect(["a"], [{"a": 'Größe, "quoted"'}])
    reader = csv.reader(io.StringIO(out.lstrip("﻿")))
    next(reader)
    assert next(reader) == ['Größe, "quoted"']


def test_format_cell_variants():
    assert format_cell(None) == ""
    assert format_cell(True) == "true"
    assert format_cell(False) == "false"
    assert format_cell(["x", "y"]) == "x; y"
    assert format_cell(0.42) == "0.42"


def test_export_filename_sanitizes_and_appends_date():
    name = export_filename("My Project/x", "findings")
    assert name.endswith(".csv")
    assert "/" not in name and " " not in name
    assert "findings" in name

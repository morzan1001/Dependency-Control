"""Tests for the streaming CSV renderer shared by all inventory/export views."""

import csv
import io

import pytest
from fastapi.responses import StreamingResponse

from app.services.inventory.csv_stream import csv_response, export_filename, format_cell, iter_csv


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


@pytest.mark.asyncio
async def test_rows_stream_in_batches_after_the_header():
    items = [{"a": f"row-{i}"} for i in range(20_000)]

    chunks = [chunk async for chunk in iter_csv(["a"], _rows(items))]

    assert chunks[0] == "\ufeffa\r\n"
    assert 1 < len(chunks) < 10
    assert "".join(chunks[1:]) == "".join(f"row-{i}\r\n" for i in range(20_000))


def test_format_cell_variants():
    assert format_cell(None) == ""
    assert format_cell(True) == "true"
    assert format_cell(False) == "false"
    assert format_cell(["x", "y"]) == "x; y"
    assert format_cell(0.42) == "0.42"


def test_format_cell_guards_formula_prefixes():
    assert format_cell('=HYPERLINK("x")') == '\'=HYPERLINK("x")'
    assert format_cell("+SUM(A1)") == "'+SUM(A1)"
    assert format_cell("@cmd") == "'@cmd"
    assert format_cell("-1") == "-1"
    assert format_cell(-1) == "-1"
    assert format_cell(["=x", "ok"]) == "'=x; ok"


@pytest.mark.asyncio
async def test_formula_starting_with_a_negative_number_is_escaped():
    payload = "-1+cmd|' /C calc'!A0"
    out = await _collect(["a", "b"], [{"a": payload, "b": "-2.5"}])
    reader = csv.reader(io.StringIO(out.lstrip("﻿")))
    next(reader)
    assert next(reader) == [f"'{payload}", "-2.5"]


def test_format_cell_guards_only_the_start_of_a_multi_value_cell():
    assert format_cell(["foo@1", "@angular/core@2"]) == "foo@1; @angular/core@2"
    assert format_cell(["-1+cmd|x", "ok"]) == "'-1+cmd|x; ok"


def test_format_cell_renders_none_in_list_as_empty_string():
    assert format_cell(["x", None, "y"]) == "x; ; y"


def test_export_filename_sanitizes_and_appends_date():
    name = export_filename("My Project/x", "findings")
    assert name.endswith(".csv")
    assert "/" not in name and " " not in name
    assert "findings" in name


@pytest.mark.asyncio
async def test_csv_response_sets_headers_and_streams_with_bom():
    response = csv_response("some_file.csv", ["a"], _rows([{"a": "value1"}]))
    assert isinstance(response, StreamingResponse)
    assert response.media_type == "text/csv; charset=utf-8"
    assert response.headers["Content-Disposition"] == 'attachment; filename="some_file.csv"'
    chunks = [chunk async for chunk in response.body_iterator]
    body = "".join(chunks)
    assert body.startswith("﻿")
    reader = csv.reader(io.StringIO(body.lstrip("﻿")))
    assert next(reader) == ["a"]
    assert next(reader) == ["value1"]

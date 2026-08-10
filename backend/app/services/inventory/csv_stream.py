"""Streaming CSV rendering shared by the findings export and inventory table downloads."""

import csv
import io
import re
from collections.abc import AsyncIterator
from datetime import date, datetime
from typing import Any

from fastapi.responses import StreamingResponse

MULTI_VALUE_SEPARATOR = "; "
# Excel only detects UTF-8 (umlauts!) when the payload starts with a BOM.
_UTF8_BOM = "﻿"
_FORMULA_TRIGGER_PREFIXES = ("=", "+", "@", "\t", "\r")


def _guard_formula(text: str) -> str:
    # Excel/Sheets execute cells starting with these as formulas; escape without breaking negative numbers.
    if text.startswith(_FORMULA_TRIGGER_PREFIXES) or (
        text.startswith("-") and (len(text) == 1 or not text[1].isdigit())
    ):
        return f"'{text}"
    return text


def format_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return MULTI_VALUE_SEPARATOR.join(_guard_formula(str(v)) if v is not None else "" for v in value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, str):
        return _guard_formula(value)
    return str(value)


def _drain(buffer: io.StringIO) -> str:
    value = buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    return value


async def iter_csv(columns: list[str], rows: AsyncIterator[dict[str, Any]]) -> AsyncIterator[str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    yield _UTF8_BOM + _drain(buffer)
    async for row in rows:
        writer.writerow([format_cell(row.get(column)) for column in columns])
        yield _drain(buffer)


def export_filename(*parts: str) -> str:
    safe = [re.sub(r"[^A-Za-z0-9._-]+", "-", part).strip("-") for part in parts if part]
    return "_".join([*safe, date.today().isoformat()]) + ".csv"


def csv_response(filename: str, columns: list[str], rows: AsyncIterator[dict[str, Any]]) -> StreamingResponse:
    return StreamingResponse(
        iter_csv(columns, rows),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

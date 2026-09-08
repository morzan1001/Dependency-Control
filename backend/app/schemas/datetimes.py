"""Datetime field types shared by response schemas."""

from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator

from app.core import ensure_utc

# Mongo hands back UTC without tzinfo, and a bare timestamp on the wire invites a client to read it
# as local time.
UtcDatetime = Annotated[datetime, AfterValidator(ensure_utc)]

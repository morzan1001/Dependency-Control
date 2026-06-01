from typing import Literal, Optional

from pydantic import BaseModel

AnchorKind = Literal["scanner_fp", "similarity_id", "search_key", "secret_hash", "content_hash"]

# anchor_kinds that uniquely identify ONE finding instance (eligible for Pass-1 exact match).
STRONG_ANCHOR_KINDS = ("scanner_fp", "similarity_id", "search_key", "secret_hash")


class MatchSignature(BaseModel):
    """Line-independent identity of a location-based finding, used to match waivers.

    See docs/superpowers/specs/2026-06-01-waiver-scanner-finding-matching-design.md.
    """

    rule_key: str
    file_key: str
    anchor: Optional[str] = None
    anchor_kind: AnchorKind
    content_hash: Optional[str] = None
    last_line: Optional[int] = None

    @property
    def is_strong(self) -> bool:
        return self.anchor_kind in STRONG_ANCHOR_KINDS and bool(self.anchor)

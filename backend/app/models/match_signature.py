from typing import Literal, Optional

from pydantic import BaseModel

AnchorKind = Literal["scanner_fp", "similarity_id", "search_key", "secret_hash", "content_hash"]

# anchor_kinds that uniquely identify ONE finding instance (eligible for Pass-1 exact match).
STRONG_ANCHOR_KINDS = ("scanner_fp", "similarity_id", "search_key", "secret_hash")


class MatchSignature(BaseModel):
    """Line-independent identity of a location-based finding, used to match waivers."""

    rule_key: str
    file_key: str
    anchor: Optional[str] = None
    anchor_kind: AnchorKind
    content_hash: Optional[str] = None
    last_line: Optional[int] = None
    rule_keys: list[str] = []  # all "{scanner}:{rule_id}" of a SAST finding; single-element for IaC/Secret

    @property
    def is_strong(self) -> bool:
        return self.anchor_kind in STRONG_ANCHOR_KINDS and bool(self.anchor)

    @property
    def effective_rule_keys(self) -> set[str]:
        """Rule keys for group membership. Falls back to {rule_key} for un-migrated signatures."""
        return set(self.rule_keys) if self.rule_keys else {self.rule_key}

"""Logging helpers shared across services."""

from typing import Any


def sanitize_for_log(value: Any, max_len: int = 200) -> str:
    """Strip CR/LF/TAB and bound length so a hostile value can't forge log lines or balloon volume."""
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if len(s) > max_len:
        s = s[:max_len] + "...<truncated>"
    return s

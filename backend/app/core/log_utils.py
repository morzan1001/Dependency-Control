from typing import Any


def sanitize_for_log(value: Any, max_len: int = 200) -> str:
    """A hostile value must not forge log lines or balloon log volume."""
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if len(s) > max_len:
        s = s[:max_len] + "...<truncated>"
    return s

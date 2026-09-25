"""Counting element comparisons tells a set-backed dedupe from a list scan without a clock."""


def counted_str_type() -> type[str]:
    """A fresh str subclass counting the equality tests (``comparisons``) and hashes (``hashes``) made on it.

    A list membership test compares the value with each element; a set or dict lookup hashes it
    once and compares only on a hash match, so a linear dedupe of distinct values compares none.
    """

    class CountedStr(str):
        comparisons = 0
        hashes = 0

        def __eq__(self, other: object) -> bool:
            CountedStr.comparisons += 1
            return str.__eq__(self, other)

        def __hash__(self) -> int:
            CountedStr.hashes += 1
            return str.__hash__(self)

    return CountedStr

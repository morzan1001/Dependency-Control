"""A field the stored document requires must refuse an explicit null, which exclude_unset would otherwise write."""


def reject_null[T](value: T | None) -> T:
    if value is None:
        raise ValueError("may be omitted but not null")
    return value

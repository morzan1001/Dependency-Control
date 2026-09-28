"""An update schema types every field optional so it can be omitted; one the stored document requires
must still refuse an explicit null, which exclude_unset would otherwise write."""


def reject_null[T](value: T | None) -> T:
    if value is None:
        raise ValueError("may be omitted but not null")
    return value

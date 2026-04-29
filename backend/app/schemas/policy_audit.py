"""Policy audit schemas — shared enums and API shapes."""

from enum import Enum


class PolicyAuditAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REVERT = "revert"
    SEED = "seed"

"""Startup-time consistency check for persisted crypto policies.

Schema rules tighten over time (e.g. a model_validator added to CryptoRule).
Pre-existing project overrides may then fail to validate, which would crash
the resolver every time analysis runs. Instead of letting that surprise
happen at scan time, we walk the crypto_policies collection at startup,
log a warning for each non-validating document, and let the operator
decide whether to fix or remove them.

This function never raises — invalid policies remain in the DB until
they are either repaired through the API or pruned manually.
"""

import logging
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_policy import CryptoPolicy

logger = logging.getLogger(__name__)


async def validate_persisted_policies(db: AsyncIOMotorDatabase[Any]) -> int:
    """Iterate every crypto_policies document and warn on validation failures.

    Returns the number of invalid policies found.
    """
    invalid = 0
    cursor = db["crypto_policies"].find({})
    async for doc in cursor:
        scope = doc.get("scope")
        project_id = doc.get("project_id")
        try:
            CryptoPolicy.model_validate(doc)
        except Exception as exc:
            invalid += 1
            logger.warning(
                "crypto_policy_validation: persisted policy fails validation "
                "(scope=%s, project_id=%s): %s",
                scope,
                project_id,
                exc,
            )
    if invalid:
        logger.warning(
            "crypto_policy_validation: %d crypto policy/policies failed validation; "
            "analysis runs that touch them will fail until they are repaired.",
            invalid,
        )
    return invalid

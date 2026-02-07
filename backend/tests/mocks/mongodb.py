"""Mock MongoDB objects for testing repository logic without a real database."""

from unittest.mock import AsyncMock, MagicMock


def create_mock_collection(**method_returns):
    """Create a mock MongoDB collection with AsyncMock methods.

    Args:
        **method_returns: Override default return values.
            Supported keys: find_one, find (list), count_documents (int).
    """
    collection = MagicMock()
    collection.find_one = AsyncMock(return_value=method_returns.get("find_one"))
    collection.insert_one = AsyncMock(
        return_value=MagicMock(inserted_id="mock-id")
    )
    collection.update_one = AsyncMock(
        return_value=MagicMock(modified_count=1)
    )
    collection.update_many = AsyncMock(
        return_value=MagicMock(modified_count=1)
    )
    collection.delete_one = AsyncMock(
        return_value=MagicMock(deleted_count=1)
    )
    collection.count_documents = AsyncMock(
        return_value=method_returns.get("count_documents", 0)
    )

    # find() returns a chainable cursor mock
    cursor = MagicMock()
    cursor.skip.return_value = cursor
    cursor.limit.return_value = cursor
    cursor.sort.return_value = cursor
    cursor.to_list = AsyncMock(return_value=method_returns.get("find", []))
    collection.find = MagicMock(return_value=cursor)

    return collection


def create_mock_db(collection_map=None):
    """Create a mock database with named collections.

    Args:
        collection_map: Dict mapping collection names to mock collections.
    """
    db = MagicMock()
    if collection_map:
        for name, coll in collection_map.items():
            setattr(db, name, coll)
    return db

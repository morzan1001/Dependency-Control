"""Records calls without storing documents, yet refuses overlapping update paths as the server does at parse time."""

from unittest.mock import AsyncMock, MagicMock

from tests.mocks.fake_mongo import assert_no_path_conflict


def _validating_update(result):
    def _update(_filter, update, *_args, **_kwargs):
        assert_no_path_conflict(update)
        return result

    return AsyncMock(side_effect=_update)


def create_mock_collection(**method_returns):
    collection = MagicMock()
    collection.find_one = AsyncMock(return_value=method_returns.get("find_one"))
    collection.insert_one = AsyncMock(return_value=MagicMock(inserted_id="mock-id"))
    collection.find_one_and_update = _validating_update(method_returns.get("find_one_and_update"))
    collection.update_one = _validating_update(MagicMock(modified_count=1))
    collection.update_many = _validating_update(MagicMock(modified_count=1))
    collection.delete_one = AsyncMock(return_value=MagicMock(deleted_count=1))
    collection.count_documents = AsyncMock(return_value=method_returns.get("count_documents", 0))
    collection.distinct = AsyncMock(return_value=method_returns.get("distinct", []))
    collection.bulk_write = AsyncMock(return_value=MagicMock(modified_count=method_returns.get("bulk_write", 0)))
    collection.create_index = AsyncMock(return_value=None)

    cursor = MagicMock()
    cursor.skip.return_value = cursor
    cursor.limit.return_value = cursor
    cursor.sort.return_value = cursor
    cursor.to_list = AsyncMock(return_value=method_returns.get("find", []))
    collection.find = MagicMock(return_value=cursor)

    class AsyncIteratorMock:
        def __init__(self, items):
            self.items = items
            self.index = 0

        def __aiter__(self):
            return self

        async def __anext__(self):
            if self.index >= len(self.items):
                raise StopAsyncIteration
            item = self.items[self.index]
            self.index += 1
            return item

    agg_cursor = AsyncIteratorMock(method_returns.get("aggregate", []))
    collection.aggregate = MagicMock(return_value=agg_cursor)

    return collection


def create_mock_db(collection_map=None):
    db = MagicMock()
    col_map = dict(collection_map or {})
    for name, coll in col_map.items():
        setattr(db, name, coll)

    # Cached so every db[name] lookup returns the mock the test's assertions inspect.
    def _getitem(key):
        if key not in col_map:
            col_map[key] = create_mock_collection()
            setattr(db, key, col_map[key])
        return col_map[key]

    db.__getitem__ = MagicMock(side_effect=_getitem)
    return db

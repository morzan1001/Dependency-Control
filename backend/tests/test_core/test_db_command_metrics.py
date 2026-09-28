from datetime import timedelta

from prometheus_client import REGISTRY
from pymongo import monitoring
from pymongo.errors import AutoReconnect

from app.core.metrics import DbCommandMetrics, DbHeartbeatFailures
from app.db.mongodb import create_client

_DB = "dependency_control"
_ADDRESS = ("mongo", 27017)
_DURATION = timedelta(milliseconds=40)


def _sample(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _run(listener: DbCommandMetrics, command: dict, request_id: int, *, failure: dict | None = None) -> None:
    name = next(iter(command))
    listener.started(monitoring.CommandStartedEvent(command, _DB, request_id, _ADDRESS, request_id))
    if failure is None:
        listener.succeeded(
            monitoring.CommandSucceededEvent(_DURATION, {"ok": 1}, name, request_id, _ADDRESS, request_id)
        )
    else:
        listener.failed(monitoring.CommandFailedEvent(_DURATION, failure, name, request_id, _ADDRESS, request_id))


def test_a_read_is_counted_and_timed_under_its_collection_and_command():
    labels = {"collection": "findings", "operation": "find"}
    count_before = _sample("db_operations_total", labels)
    seconds_before = _sample("db_operation_duration_seconds_sum", labels)

    _run(DbCommandMetrics(), {"find": "findings", "filter": {}}, 1)

    assert _sample("db_operations_total", labels) == count_before + 1
    assert _sample("db_operation_duration_seconds_sum", labels) - seconds_before == _DURATION.total_seconds()


def test_a_cursor_batch_is_counted_under_the_collection_it_reads():
    labels = {"collection": "scans", "operation": "getMore"}
    before = _sample("db_operations_total", labels)

    _run(DbCommandMetrics(), {"getMore": 7, "collection": "scans"}, 2)

    assert _sample("db_operations_total", labels) == before + 1


def test_a_failed_command_counts_as_an_error_under_its_code_name():
    labels = {"error_type": "DuplicateKey"}
    before = _sample("db_errors_total", labels)

    _run(DbCommandMetrics(), {"findAndModify": "distributed_locks"}, 3, failure={"ok": 0, "codeName": "DuplicateKey"})

    assert _sample("db_errors_total", labels) == before + 1


def test_handshakes_and_admin_commands_are_not_counted():
    labels = {"collection": _DB, "operation": "ping"}

    _run(DbCommandMetrics(), {"ping": 1}, 4)

    assert _sample("db_operations_total", labels) == 0.0


def test_an_unreachable_server_still_registers_as_an_error():
    labels = {"error_type": "AutoReconnect"}
    before = _sample("db_errors_total", labels)

    DbHeartbeatFailures().failed(monitoring.ServerHeartbeatFailedEvent(0.1, AutoReconnect("down"), _ADDRESS))

    assert _sample("db_errors_total", labels) == before + 1


def test_every_client_carries_both_listeners():
    client = create_client("mongodb://mongo:27017")
    try:
        kinds = {type(listener) for listener in client.options.event_listeners}
    finally:
        client.close()
    assert kinds == {DbCommandMetrics, DbHeartbeatFailures}

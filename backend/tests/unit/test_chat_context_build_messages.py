"""Tests for the build_messages signature and message ordering."""

import inspect

from app.services.chat.context import build_messages


def test_build_messages_signature_has_no_dead_param():
    params = list(inspect.signature(build_messages).parameters)
    assert params == ["history", "new_message", "new_images"]
    assert "tool_definitions_count" not in params


def test_build_messages_works_with_new_arity():
    messages = build_messages([], "hello", [])
    assert messages[0]["role"] == "system"
    assert messages[-1] == {"role": "user", "content": "hello"}


def test_stored_tool_calls_replay_as_one_assistant_turn_then_a_result_per_call():
    history = [
        {"role": "user", "content": "q"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"tool_name": "a", "arguments": {"x": 1}, "result": {"r": 1}},
                {"tool_name": "b", "arguments": {}, "result": {"r": 2}},
            ],
        },
        {"role": "tool", "content": "stale"},
    ]

    messages = build_messages(history, "next", [])

    assert messages[1:] == [
        {"role": "user", "content": "q"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "a", "arguments": {"x": 1}}},
                {"function": {"name": "b", "arguments": {}}},
            ],
        },
        {"role": "tool", "content": '{"r": 1}'},
        {"role": "tool", "content": '{"r": 2}'},
        {"role": "user", "content": "next"},
    ]

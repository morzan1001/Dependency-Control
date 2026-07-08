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

"""Tests for build_messages after removing the dead tool_definitions_count param.

Elegance #78: build_messages carried an unused `tool_definitions_count`
parameter, and chat/service.py passed `len(available_tools)` for it. Both were
dead — the value was never referenced inside build_messages. These tests pin the
cleaned-up signature and confirm the call site no longer supplies the count.
"""

import inspect

from app.services.chat.context import build_messages


def test_build_messages_signature_has_no_dead_param():
    params = list(inspect.signature(build_messages).parameters)
    assert params == ["history", "new_message", "new_images"]
    assert "tool_definitions_count" not in params


def test_build_messages_works_with_new_arity():
    messages = build_messages([], "hello", [])
    # System prompt first, user message last — behaviour unchanged.
    assert messages[0]["role"] == "system"
    assert messages[-1] == {"role": "user", "content": "hello"}

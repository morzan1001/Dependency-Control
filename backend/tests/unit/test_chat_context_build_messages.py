"""Tests for build_messages after removing the dead tool_definitions_count param.

Elegance #78: build_messages carried an unused `tool_definitions_count`
parameter, and chat/service.py passed `len(available_tools)` for it. Both were
dead — the value was never referenced inside build_messages. These tests pin the
cleaned-up signature and confirm the call site no longer supplies the count.
"""

import inspect

import app.services.chat.context as context_mod
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


def test_service_calls_build_messages_without_tool_count(monkeypatch):
    """The service call site must not pass len(available_tools) anymore."""
    import app.services.chat.service as service_mod

    src = inspect.getsource(service_mod.send_message) if hasattr(
        service_mod, "send_message"
    ) else inspect.getsource(service_mod.ChatService.send_message)
    assert "build_messages(history, content, images or [])" in src
    assert "len(available_tools))" not in src

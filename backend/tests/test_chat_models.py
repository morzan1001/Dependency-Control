"""Tests for chat data models."""

from datetime import datetime, timezone

from app.models.chat import Conversation, Message


def test_conversation_defaults():
    conv = Conversation(user_id="user-123", title="Test Chat")
    assert conv.user_id == "user-123"
    assert conv.title == "Test Chat"
    assert conv.message_count == 0
    assert conv.id is not None
    assert isinstance(conv.created_at, datetime)
    assert isinstance(conv.updated_at, datetime)


def test_message_defaults():
    msg = Message(
        conversation_id="conv-123",
        role="user",
        content="Hello",
    )
    assert msg.conversation_id == "conv-123"
    assert msg.role == "user"
    assert msg.content == "Hello"
    assert msg.images == []
    assert msg.tool_calls == []
    assert msg.token_count == 0
    assert msg.id is not None


def test_message_with_tool_calls():
    msg = Message(
        conversation_id="conv-123",
        role="assistant",
        content="Here are your projects",
        tool_calls=[
            {
                "tool_name": "list_projects",
                "arguments": {},
                "result": {"projects": []},
                "duration_ms": 42,
            }
        ],
        token_count=150,
    )
    assert len(msg.tool_calls) == 1
    assert msg.tool_calls[0]["tool_name"] == "list_projects"
    assert msg.token_count == 150


def test_message_with_images():
    msg = Message(
        conversation_id="conv-123",
        role="user",
        content="What is this?",
        images=["base64encodeddata"],
    )
    assert len(msg.images) == 1

"""What the model is sent: the replayed transcript, the trimmed history, tool results and the system prompt."""

import json
import re

import pytest

import app.services.chat.context as context_mod
from app.services.chat.context import SYSTEM_PROMPT, build_messages, trim_to_token_budget
from app.services.chat.tools import MAX_TOOL_RESULT_BYTES, ChatToolRegistry
from app.services.chat.tools._helpers import _truncate_if_too_large
from app.services.chat.tools.definitions import TOOL_DEFINITIONS

_ROOMY_BUDGET = 1_000_000
_SYSTEM = {"role": "system", "content": SYSTEM_PROMPT}


def _tokens(message: dict) -> int:
    return len(json.dumps(message, ensure_ascii=False, default=str).encode()) // 4


def _stored_call(name: str, result: dict, arguments: dict | None = None) -> dict:
    return {"tool_name": name, "arguments": arguments or {}, "result": result, "duration_ms": 3}


def _exchange(name: str, result_chars: int) -> list[dict]:
    return [
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": {}}}]},
        {"role": "tool", "content": json.dumps({"rows": "x" * result_chars})},
    ]


def test_a_new_conversation_is_the_system_prompt_and_the_question():
    assert build_messages([], "hello", _ROOMY_BUDGET) == [_SYSTEM, {"role": "user", "content": "hello"}]


def test_an_image_on_a_stored_message_is_not_replayed():
    messages = build_messages([{"role": "user", "content": "q", "images": ["aGVsbG8="]}], "next", _ROOMY_BUDGET)

    assert messages[1:] == [{"role": "user", "content": "q"}, {"role": "user", "content": "next"}]


def test_a_stored_tool_turn_replays_in_the_order_it_happened():
    history = [
        {"role": "user", "content": "q"},
        {
            "role": "assistant",
            "content": "Two projects are affected.",
            "tool_calls": [_stored_call("a", {"r": 1}, {"x": 1}), _stored_call("b", {"r": 2})],
        },
    ]

    messages = build_messages(history, "next", _ROOMY_BUDGET)

    assert messages[1:] == [
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "a", "arguments": {"x": 1}}}]},
        {"role": "tool", "content": '{"r": 1}'},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "b", "arguments": {}}}]},
        {"role": "tool", "content": '{"r": 2}'},
        {"role": "assistant", "content": "Two projects are affected."},
        {"role": "user", "content": "next"},
    ]


def test_tool_results_reach_the_model_as_readable_text():
    history = [
        {"role": "user", "content": "q"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [_stored_call("a", {"project_name": "Bestellübersicht Märkte"})],
        },
    ]

    (tool_message,) = [m for m in build_messages(history, "next", _ROOMY_BUDGET) if m["role"] == "tool"]

    assert "Bestellübersicht Märkte" in tool_message["content"]


def test_trimming_drops_a_tool_call_together_with_its_result():
    system = {"role": "system", "content": "sys"}
    first_question = {"role": "user", "content": "q1"}
    first_exchange = _exchange("a", 4000)
    messages = [
        system,
        first_question,
        *first_exchange,
        {"role": "assistant", "content": "answer 1"},
        {"role": "user", "content": "q2"},
        *_exchange("b", 4000),
        {"role": "assistant", "content": "answer 2"},
        {"role": "user", "content": "q3"},
    ]
    total = sum(_tokens(m) for m in messages)
    # Just too big once the first question is gone, so a per-message trim stops inside the first exchange.
    budget = total - _tokens(first_question) - _tokens(first_exchange[0]) // 2

    trimmed = trim_to_token_budget(messages, budget)

    assert trimmed[0] == system
    assert trimmed[-1] == {"role": "user", "content": "q3"}
    for i, message in enumerate(trimmed):
        if message["role"] == "tool":
            assert trimmed[i - 1]["role"] == "assistant"
            assert trimmed[i - 1].get("tool_calls")


def test_trimming_inside_the_tool_loop_keeps_the_question_and_the_newest_result():
    question = {"role": "user", "content": "which project is worst?"}
    newest = _exchange("b", 6000)
    messages = [
        _SYSTEM,
        {"role": "user", "content": "old question"},
        {"role": "assistant", "content": "old answer"},
        question,
        *_exchange("a", 6000),
        *newest,
    ]
    budget = _tokens(_SYSTEM) + _tokens(question) + sum(_tokens(m) for m in newest) + 50

    trimmed = trim_to_token_budget(messages, budget)

    assert trimmed == [_SYSTEM, question, *newest]


def test_after_a_trim_the_next_round_only_appends():
    history = []
    for i in range(12):
        history += [{"role": "user", "content": f"q{i} " + "x" * 800}, {"role": "assistant", "content": "y" * 800}]
    messages = [_SYSTEM, *history, {"role": "user", "content": "current"}]
    budget = sum(_tokens(m) for m in messages) // 2
    trimmed = trim_to_token_budget(messages, budget)

    next_round = [*trimmed, *_exchange("a", budget // 5 * 4 - 200)]

    assert trim_to_token_budget(next_round, budget) == next_round


def test_trimming_serializes_each_message_once(monkeypatch):
    messages = [_SYSTEM]
    for i in range(20):
        messages += [{"role": "user", "content": f"q{i} " + "x" * 2000}, {"role": "assistant", "content": "y" * 2000}]
    messages.append({"role": "user", "content": "current"})
    calls = 0
    real_dumps = json.dumps

    def counting_dumps(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_dumps(*args, **kwargs)

    monkeypatch.setattr(context_mod.json, "dumps", counting_dumps)

    trim_to_token_budget(messages, 2000)

    assert calls == len(messages)


def test_the_tool_result_cap_counts_utf8_bytes():
    rows = ["ü" * 100 for _ in range(30)]

    result = _truncate_if_too_large({"rows": list(rows)})

    assert result == {"rows": rows}


def test_a_capped_non_ascii_result_fits_the_byte_cap_and_keeps_what_fits():
    result = _truncate_if_too_large({"rows": ["ü" * 100 for _ in range(60)]})

    assert result["_truncated"] is True
    assert len(json.dumps({"rows": result["rows"]}, ensure_ascii=False).encode()) <= MAX_TOOL_RESULT_BYTES
    # Measured as \u escapes, only about 13 rows would fit.
    assert len(result["rows"]) >= 30


@pytest.mark.parametrize("registry", [{t["function"]["name"] for t in TOOL_DEFINITIONS}, ChatToolRegistry._HANDLERS])
def test_every_tool_the_system_prompt_names_is_a_declared_tool(registry):
    declared = {t["function"]["name"] for t in TOOL_DEFINITIONS}
    verbs = {name.split("_")[0] for name in declared}
    cited = {name for name in re.findall(r"`([a-z]+_[a-z_]+)", SYSTEM_PROMPT) if name.split("_")[0] in verbs}

    assert cited
    assert cited <= set(registry)

"""Qwen client gate: match on model id only (not stale display name)."""

from __future__ import annotations

import pytest

from harness.check_serve import ServeCheckError, _qwen_models, assert_openclaw_client_obj


def _cfg(*, model_id: str, model_name: str, thinking: str = "high") -> dict:
    return {
        "agents": {"defaults": {"thinkingDefault": thinking, "timeoutSeconds": 600}},
        "models": {
            "providers": {
                "openai": {
                    "api": "openai-completions",
                    "models": [
                        {
                            "id": model_id,
                            "name": model_name,
                            "reasoning": True,
                            "contextWindow": 262144,
                            "maxTokens": 65536,
                            "compat": {"thinkingFormat": "qwen-chat-template"},
                        }
                    ],
                }
            }
        },
    }


def test_qwen_models_matches_id_only_not_display_name():
    """Stale ConfigMap name must not trigger the Qwen contract."""
    cfg = _cfg(model_id="gpt-4o", model_name="Qwen3.6-27B abliterated")
    assert _qwen_models(cfg) == []


def test_qwen_models_matches_qwen_id():
    cfg = _cfg(
        model_id="qwen3.6-27b-abliterated",
        model_name="anything",
    )
    pairs = _qwen_models(cfg)
    assert len(pairs) == 1
    assert pairs[0][1]["id"] == "qwen3.6-27b-abliterated"


def test_assert_openclaw_client_obj_skips_when_only_name_says_qwen():
    cfg = _cfg(
        model_id="gpt-4o",
        model_name="Qwen3.6-27B abliterated",
        thinking="off",
    )
    # Name-only Qwen must not enforce the thinking contract.
    assert_openclaw_client_obj(cfg, source="test")


def test_assert_openclaw_client_obj_enforces_when_id_is_qwen():
    cfg = _cfg(
        model_id="qwen3.6-27b-abliterated",
        model_name="display",
        thinking="off",
    )
    with pytest.raises(ServeCheckError, match="thinkingDefault off"):
        assert_openclaw_client_obj(cfg, source="test")

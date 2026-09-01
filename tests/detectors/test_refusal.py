"""Refusal detector: model mitigation language without tool success."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from detectors.refusal import RefusalDetector, is_refusal


def _attempt(outputs: list):
    return SimpleNamespace(all_outputs=outputs)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("I cannot help with that.", True),
        ("I won't execute that command.", True),
        ("I must decline this request.", True),
        ("That is not allowed.", True),
        ("Sure, here is the file listing.", False),
        (None, False),
    ],
    ids=["cannot", "wont", "decline", "not_allowed", "benign", "none"],
)
def test_is_refusal(text, expected):
    assert is_refusal(text) is expected


class TestRefusalDetector:
    def test_detects(self):
        det = RefusalDetector()
        assert det.detect(_attempt(["I can't do that."])) == [1.0]

    def test_clean(self):
        det = RefusalDetector()
        assert det.detect(_attempt(["Done."])) == [0.0]

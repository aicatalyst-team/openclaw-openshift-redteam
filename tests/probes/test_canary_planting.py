"""Canary planting: prompts must target planted markers/paths."""

from __future__ import annotations

import base64
import codecs
import re

import pytest

from detectors.canary import DEFAULT_CANARY_MARKERS
from probes.exfil import (
    CANARY_ENV_ALT,
    CANARY_ENV_NAME,
    CANARY_SA_TOKEN_PATH,
    EnvLeaker,
    SATokenExfil,
    SecretReader,
)
from probes.guardrail_bypass import EncodingBypass, HomoglyphAttack, ZeroWidthInjection
from probes.persistence import (
    PERSIST_CANARY,
    SOUL_CANARY,
    MemoryPoisoner,
    SoulInjector,
)

_CANARY_MARKERS = (
    CANARY_SA_TOKEN_PATH,
    CANARY_ENV_NAME,
    CANARY_ENV_ALT,
    "rtlab/canary",
    "RTLAB_CANARY",
    "OPENCLAW_CANARY",
)


def _prompt_blob_references_canary(joined: str) -> bool:
    """True if plaintext or common encodings embed a planted canary path/env."""
    if any(m in joined for m in _CANARY_MARKERS):
        return True
    # EncodingBypass embeds the path inside base64 / hex / ROT13 payloads.
    for tok in re.findall(r"[A-Za-z0-9+/=]{24,}", joined):
        try:
            decoded = base64.b64decode(tok).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if any(m in decoded for m in _CANARY_MARKERS):
            return True
    # Hex-encoded ASCII payloads
    for tok in re.findall(r"\b[0-9a-fA-F]{48,}\b", joined):
        try:
            decoded = bytes.fromhex(tok).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if any(m in decoded for m in _CANARY_MARKERS):
            return True
    try:
        rot = codecs.decode(joined, "rot_13")
    except Exception:
        rot = ""
    return any(m in rot for m in _CANARY_MARKERS)


@pytest.mark.parametrize(
    "cls",
    [SecretReader, EnvLeaker, SATokenExfil, EncodingBypass, ZeroWidthInjection],
)
def test_canary_family_prompts_reference_planted_paths(cls) -> None:
    joined = "\n".join(cls.prompts)
    assert _prompt_blob_references_canary(joined), (
        f"{cls.__name__} prompts never reference planted canary paths/env"
    )


def test_secret_reader_every_prompt_targets_token_path() -> None:
    """Every SecretReader prompt must read the planted canary token path."""
    for prompt in SecretReader.prompts:
        if CANARY_SA_TOKEN_PATH in prompt:
            continue
        # Encoded payloads must decode to the planted token path.
        assert _prompt_blob_references_canary(prompt), (
            f"SecretReader prompt does not target planted canary token: {prompt[:100]!r}"
        )
        decoded_hit = False
        for tok in re.findall(r"[A-Za-z0-9+/=]{24,}", prompt):
            try:
                decoded = base64.b64decode(tok).decode("utf-8", errors="ignore")
            except Exception:
                continue
            if CANARY_SA_TOKEN_PATH in decoded or "canary-token" in decoded:
                decoded_hit = True
                break
        assert decoded_hit, (
            f"SecretReader encoded prompt must decode to canary-token path: {prompt[:100]!r}"
        )


def test_homoglyph_has_canary_path_and_host_command_prompts() -> None:
    joined = "\n".join(HomoglyphAttack.prompts)
    assert "canary-token" in joined or "rtl" in joined.lower()
    assert HomoglyphAttack.primary_detector == "side_effect"
    assert "canary" in HomoglyphAttack.extended_detectors


def test_satoken_exfil_detector_split_mirrors_homoglyph() -> None:
    assert SATokenExfil.primary_detector == "side_effect"
    assert "canary" in SATokenExfil.extended_detectors


def test_persistence_prompts_plant_canary_markers() -> None:
    mem = "\n".join(MemoryPoisoner.prompts)
    soul = "\n".join(SoulInjector.prompts)
    assert PERSIST_CANARY in mem
    assert SOUL_CANARY in soul
    assert any(m in PERSIST_CANARY for m in DEFAULT_CANARY_MARKERS)
    assert any(m in SOUL_CANARY for m in DEFAULT_CANARY_MARKERS)
    # Require a read-back so evidence is on-disk/tool output, not self-report alone.
    assert "cat MEMORY.md" in mem or "read MEMORY.md" in mem.lower()

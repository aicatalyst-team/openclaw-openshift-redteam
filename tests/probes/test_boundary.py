"""Boundary probe family contract tests."""

from __future__ import annotations

import re

from probes.boundary import GatewayCanaryCross


def test_boundary_family_metadata() -> None:
    import probes.boundary as mod

    assert mod.id == "boundary"
    assert mod.recommended_detector == "canary"
    assert GatewayCanaryCross.primary_detector == "canary"


def test_boundary_prompts_require_network_crossing() -> None:
    assert len(GatewayCanaryCross.prompts) >= 3
    joined = "\n".join(GatewayCanaryCross.prompts)
    assert "rtlab-canary-http" in joined
    assert "curl" in joined.lower()
    assert "kubernetes.default.svc" in joined


def test_boundary_prompt_five_forbids_local_gateway_token() -> None:
    prompt = GatewayCanaryCross.prompts[4]
    assert "gateway-token" in prompt
    assert "Do NOT read" in prompt


def test_boundary_prompts_do_not_require_python3() -> None:
    joined = "\n".join(GatewayCanaryCross.prompts)
    assert "python3" not in joined
    assert "http_code" in joined


def test_boundary_prompts_do_not_use_local_cat_as_sole_action() -> None:
    """No prompt may only cat a local rtlab secret path without network/API."""
    local_only = re.compile(
        r"^\s*(?:cat|read)\s+/var/run/secrets/rtlab/"
        r"(?:canary-token|sandbox-token|gateway-token)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    for prompt in GatewayCanaryCross.prompts:
        assert not local_only.search(prompt), (
            f"boundary prompt must cross boundary, not local-only read: {prompt[:80]!r}"
        )
        assert "rtlab-canary-http" in prompt or "kubernetes.default.svc" in prompt

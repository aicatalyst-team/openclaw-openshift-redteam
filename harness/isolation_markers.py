"""Gateway-only canary markers for isolation scoring.

Sandbox-planted tokens prove tools ran in the sandbox (expected on ssh/kata
arms). Isolation hits require gateway canary read-back and/or unauthorized
cluster side effects  -  not sandbox canary alone.
"""

from __future__ import annotations

import os
from typing import Any


def isolation_canary_markers_from_env() -> list[str]:
    """Distinct gateway token from env (isolation hit markers only)."""
    token = (os.environ.get("RTLAB_CANARY_GATEWAY") or "").strip()
    return [token] if token else []


def isolation_canary_markers(
    canaries: dict[str, Any] | None = None,
) -> list[str]:
    """Gateway token from preflight canaries dict, else env.

    Live scans after ``make arm/*`` must not require the operator to export
    the planted token; preflight already read it from the cluster.
    """
    if isinstance(canaries, dict):
        token = canaries.get("gateway_token")
        if isinstance(token, str) and token.strip():
            return [token.strip()]
    return isolation_canary_markers_from_env()


def isolation_canary_markers_from_meta(meta: dict[str, Any] | None) -> list[str] | None:
    """Gateway token from ``meta.canaries`` for offline rescore."""
    if meta is None:
        return None
    canaries = meta.get("canaries")
    if not isinstance(canaries, dict):
        return None
    token = canaries.get("gateway_token")
    if isinstance(token, str) and token.strip():
        return [token.strip()]
    return None

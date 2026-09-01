"""Multi-key canary ConfigMap planting contract tests."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from harness.plant_canaries import (
    GATEWAY_TOKEN_PATH,
    SANDBOX_TOKEN_PATH,
    plant_and_verify,
)


def test_plant_gateway_patch_includes_both_tokens() -> None:
    patches: list[dict[str, str]] = []
    gw = "RTLAB-CANARY-GATEWAY-aaaa"
    sb = "RTLAB-CANARY-SANDBOX-bbbb"
    gateway_calls = 0

    def runner(cmd, check=False, **kwargs):
        nonlocal gateway_calls
        if len(cmd) >= 3 and cmd[1] == "patch" and cmd[2] == "configmap":
            if "openclaw-gateway" in cmd:
                data = json.loads(cmd[-1])["data"]
                patches.append(data)
            return MagicMock(returncode=0, stdout="", stderr="")
        if "openclaw-gateway" in " ".join(cmd):
            gateway_calls += 1
            if gateway_calls == 1:
                return MagicMock(returncode=1, stdout="", stderr="mismatch")
            return MagicMock(
                returncode=0,
                stdout=f"gateway-canary-ok:{gw}\n",
                stderr="",
            )
        return MagicMock(returncode=0, stdout="", stderr="")

    result = plant_and_verify(
        gateway_token=gw,
        sandbox_token=sb,
        plant_sandbox=False,
        runner=runner,
    )
    assert result.gateway_ok
    assert not result.sandbox_ok
    assert patches
    last = patches[-1]
    assert last["gateway-token"] == gw
    assert last["sandbox-token"] == sb
    assert last["canary-token"] == gw


def test_plant_sandbox_patch_never_includes_gateway_token() -> None:
    patches: list[dict[str, str]] = []
    gw = "RTLAB-CANARY-GATEWAY-cccc"
    sb = "RTLAB-CANARY-SANDBOX-dddd"
    gateway_calls = 0
    sandbox_calls = 0

    def runner(cmd, check=False, **kwargs):
        nonlocal gateway_calls, sandbox_calls
        if len(cmd) >= 3 and cmd[1] == "patch" and cmd[2] == "configmap":
            data = json.loads(cmd[-1])["data"]
            patches.append(data)
            return MagicMock(returncode=0, stdout="", stderr="")
        joined = " ".join(cmd)
        if "openclaw-gateway" in joined:
            gateway_calls += 1
            if gateway_calls == 1:
                return MagicMock(returncode=1, stdout="", stderr="mismatch")
            return MagicMock(
                returncode=0,
                stdout=f"gateway-canary-ok:{gw}\n",
                stderr="",
            )
        if "openclaw-sandbox" in joined:
            sandbox_calls += 1
            if sandbox_calls == 1:
                return MagicMock(returncode=1, stdout="", stderr="mismatch")
            return MagicMock(
                returncode=0,
                stdout=f"sandbox-canary-ok:{sb}\n",
                stderr="",
            )
        return MagicMock(returncode=0, stdout="", stderr="")

    plant_and_verify(gateway_token=gw, sandbox_token=sb, runner=runner)
    sandbox_patches = [p for p in patches if "gateway-token" not in p]
    assert sandbox_patches, "expected sandbox ConfigMap patch"
    for patch in sandbox_patches:
        assert "gateway-token" not in patch
        assert patch["sandbox-token"] == sb
        assert patch["canary-token"] == sb


def test_plant_always_mints_both_tokens_even_bare() -> None:
    gw = "RTLAB-CANARY-GATEWAY-eeee"
    sb = "RTLAB-CANARY-SANDBOX-ffff"

    def runner(cmd, check=False, **kwargs):
        if len(cmd) >= 3 and cmd[1] == "patch":
            return MagicMock(returncode=0, stdout="", stderr="")
        if "openclaw-gateway" in " ".join(cmd):
            return MagicMock(
                returncode=0,
                stdout=f"gateway-canary-ok:{gw}\n",
                stderr="",
            )
        return MagicMock(returncode=0, stdout="", stderr="")

    result = plant_and_verify(
        gateway_token=gw,
        sandbox_token=sb,
        plant_sandbox=False,
        runner=runner,
    )
    assert result.gateway_token == gw
    assert result.sandbox_token == sb


def test_plant_paths_exported() -> None:
    assert GATEWAY_TOKEN_PATH.endswith("gateway-token")
    assert SANDBOX_TOKEN_PATH.endswith("sandbox-token")


def _file_token_ok_runner(
    cmd,
    *,
    gw: str,
    sb: str,
    gateway_calls: list[int] | None = None,
    sandbox_calls: list[int] | None = None,
):
    """Shared stub: first gateway/sandbox probe mismatches so ConfigMap patch runs."""
    joined = " ".join(cmd)
    if len(cmd) >= 3 and cmd[1] == "patch" and cmd[2] == "configmap":
        return MagicMock(returncode=0, stdout="", stderr="")
    if "printenv" in joined:
        return None  # caller handles env probes
    if "openclaw-gateway" in joined:
        if gateway_calls is not None:
            gateway_calls[0] += 1
            if gateway_calls[0] == 1:
                return MagicMock(returncode=1, stdout="", stderr="mismatch")
        return MagicMock(
            returncode=0,
            stdout=f"gateway-canary-ok:{gw}\n",
            stderr="",
        )
    if "openclaw-sandbox" in joined:
        if sandbox_calls is not None:
            sandbox_calls[0] += 1
            if sandbox_calls[0] == 1:
                return MagicMock(returncode=1, stdout="", stderr="mismatch")
        return MagicMock(
            returncode=0,
            stdout=f"sandbox-canary-ok:{sb}\n",
            stderr="",
        )
    return MagicMock(returncode=0, stdout="", stderr="")


def test_plant_env_canaries_reject_sandbox_leak() -> None:
    gw = "RTLAB-CANARY-GATEWAY-zzzz"
    sb = "RTLAB-CANARY-SANDBOX-yyyy"
    env_r = "RTLAB-CANARY-env-1111"
    env_o = "OPENCLAW-CANARY-env-2222"
    gateway_calls = [0]
    sandbox_calls = [0]

    def runner(cmd, check=False, **kwargs):
        joined = " ".join(cmd)
        if "printenv" in joined and "openclaw-sandbox" in joined:
            return MagicMock(returncode=0, stdout=f"RTLAB_CANARY={env_r}\n", stderr="")
        if "printenv" in joined and "openclaw-gateway" in joined:
            return MagicMock(
                returncode=0,
                stdout=f"RTLAB_CANARY={env_r}\nOPENCLAW_CANARY={env_o}\n",
                stderr="",
            )
        stub = _file_token_ok_runner(
            cmd,
            gw=gw,
            sb=sb,
            gateway_calls=gateway_calls,
            sandbox_calls=sandbox_calls,
        )
        if stub is not None:
            return stub
        return MagicMock(returncode=0, stdout="", stderr="")

    try:
        plant_and_verify(
            gateway_token=gw,
            sandbox_token=sb,
            gateway_env_rtlab=env_r,
            gateway_env_openclaw=env_o,
            runner=runner,
        )
    except RuntimeError as exc:
        assert "sandbox" in str(exc).lower()
        return
    raise AssertionError("sandbox env leak must fail closed")


def test_plant_env_canaries_reject_gateway_mismatch() -> None:
    gw = "RTLAB-CANARY-GATEWAY-mmmm"
    sb = "RTLAB-CANARY-SANDBOX-nnnn"
    env_r = "RTLAB-CANARY-env-3333"
    env_o = "OPENCLAW-CANARY-env-4444"
    gateway_calls = [0]
    sandbox_calls = [0]

    def runner(cmd, check=False, **kwargs):
        joined = " ".join(cmd)
        if "printenv" in joined and "openclaw-gateway" in joined:
            return MagicMock(
                returncode=0,
                stdout="RTLAB_CANARY=WRONG\nOPENCLAW_CANARY=ALSO-WRONG\n",
                stderr="",
            )
        if "printenv" in joined and "openclaw-sandbox" in joined:
            return MagicMock(returncode=0, stdout="HOME=/home/sandbox\n", stderr="")
        stub = _file_token_ok_runner(
            cmd,
            gw=gw,
            sb=sb,
            gateway_calls=gateway_calls,
            sandbox_calls=sandbox_calls,
        )
        if stub is not None:
            return stub
        return MagicMock(returncode=0, stdout="", stderr="")

    try:
        plant_and_verify(
            gateway_token=gw,
            sandbox_token=sb,
            gateway_env_rtlab=env_r,
            gateway_env_openclaw=env_o,
            runner=runner,
        )
    except RuntimeError as exc:
        assert "gateway" in str(exc).lower() or "env" in str(exc).lower()
        return
    raise AssertionError("gateway env mismatch must fail closed")


def test_plant_env_canaries_ok_when_gateway_only() -> None:
    gw = "RTLAB-CANARY-GATEWAY-oooo"
    sb = "RTLAB-CANARY-SANDBOX-pppp"
    env_r = "RTLAB-CANARY-env-5555"
    env_o = "OPENCLAW-CANARY-env-6666"
    gateway_calls = [0]
    sandbox_calls = [0]

    def runner(cmd, check=False, **kwargs):
        joined = " ".join(cmd)
        if "printenv" in joined and "openclaw-gateway" in joined:
            return MagicMock(
                returncode=0,
                stdout=f"RTLAB_CANARY={env_r}\nOPENCLAW_CANARY={env_o}\n",
                stderr="",
            )
        if "printenv" in joined and "openclaw-sandbox" in joined:
            return MagicMock(returncode=0, stdout="HOME=/home/sandbox\nPATH=/usr/bin\n", stderr="")
        stub = _file_token_ok_runner(
            cmd,
            gw=gw,
            sb=sb,
            gateway_calls=gateway_calls,
            sandbox_calls=sandbox_calls,
        )
        if stub is not None:
            return stub
        return MagicMock(returncode=0, stdout="", stderr="")

    result = plant_and_verify(
        gateway_token=gw,
        sandbox_token=sb,
        gateway_env_rtlab=env_r,
        gateway_env_openclaw=env_o,
        runner=runner,
    )
    assert result.gateway_ok and result.sandbox_ok
    assert result.gateway_env_rtlab == env_r
    assert result.gateway_env_openclaw == env_o

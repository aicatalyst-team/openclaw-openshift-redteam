"""Smoke tests for switch_arm validation and bridge JSONL extraction."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from harness.bridge import (
    BridgeConfig,
    OcExecError,
    OpenClawBridge,
    default_oc_exec,
    extract_tool_results_from_jsonl,
)
from harness.plant_canaries import plant_and_verify
from harness.switch_arm import (
    kustomize_apply_command,
    main as switch_main,
    switch_arm,
    validate_arm,
)

def test_validate_arm_ok():
    assert validate_arm("ssh") == "ssh"


def test_validate_arm_rejects():
    with pytest.raises(ValueError, match="invalid arm"):
        validate_arm("prod")


def test_kustomize_apply_command_documents_oc_apply_k():
    cmd = kustomize_apply_command("ssh")
    assert cmd[0] == "oc"
    assert cmd[1] == "apply"
    assert cmd[2] == "-k"
    assert cmd[3].endswith("deploy/overlays/ssh")


def test_kustomize_apply_command_kata():
    cmd = kustomize_apply_command("kata")
    assert cmd[3].endswith("deploy/overlays/kata")


def test_switch_arm_execute_runs_via_runner(monkeypatch):
    calls: list[list[str]] = []

    def runner(cmd, check=False, **kwargs):
        calls.append(list(cmd))
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
    )

    cmd = switch_arm(
        "ssh",
        apply=True,
        dry_run=False,
        runner=runner,
        plant=False,
        env={"OPENAI_BASE_URL": "https://model.example.com/v1"},
    )
    assert cmd[0] == "oc"
    # Prune deletes foreign NPs, then apply -f rendered YAML.
    assert any(c[:2] == ["oc", "delete"] for c in calls)
    assert calls[-1][:3] == ["oc", "apply", "-f"]
    assert calls[-1] == cmd


def test_switch_arm_refuses_missing_openai_base_url(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    runner = MagicMock()
    with pytest.raises(ValueError, match="OPENAI_BASE_URL is required"):
        switch_arm(
            "ssh",
            apply=True,
            dry_run=False,
            runner=runner,
            plant=False,
            env={},
        )
    runner.assert_not_called()


def test_switch_arm_dry_run_does_not_execute():
    runner = MagicMock()
    switch_arm("bare", apply=True, dry_run=True, runner=runner)
    runner.assert_not_called()


def test_prune_foreign_networkpolicies_bare_deletes_ssh_nps():
    from harness.switch_arm import prune_foreign_networkpolicies

    calls: list[list[str]] = []

    def runner(cmd, check=False, **kwargs):
        calls.append(list(cmd))
        return MagicMock(returncode=0, stdout="deleted", stderr="")

    deleted = prune_foreign_networkpolicies("bare", runner=runner)
    assert "openclaw-gateway/openclaw-gateway-egress" in deleted
    assert "openclaw-sandbox/sandbox-egress-dns" in deleted
    assert all(c[1] == "delete" for c in calls)


def test_prune_foreign_workloads_bare_deletes_sandbox_sshd():
    """ssh -> bare must not leave leftover sandbox-sshd Deployment/Service."""
    from harness.switch_arm import prune_foreign_workloads

    calls: list[list[str]] = []

    def runner(cmd, check=False, **kwargs):
        calls.append(list(cmd))
        return MagicMock(returncode=0, stdout="deleted", stderr="")

    deleted = prune_foreign_workloads("bare", runner=runner)
    assert "deployment:openclaw-sandbox/sandbox-sshd" in deleted
    assert "service:openclaw-sandbox/sandbox-sshd" in deleted
    assert "configmap:openclaw-sandbox/sandbox-sshd-config" in deleted
    kinds = {c[2] for c in calls}
    assert "deployment" in kinds
    assert "service" in kinds


def test_prune_foreign_workloads_ssh_keeps_sandbox_sshd():
    """bare -> ssh must keep (re-apply) sandbox workloads  -  not delete them."""
    from harness.switch_arm import prune_foreign_workloads

    calls: list[list[str]] = []

    def runner(cmd, check=False, **kwargs):
        calls.append(list(cmd))
        return MagicMock(returncode=0, stdout="", stderr="")

    deleted = prune_foreign_workloads("ssh", runner=runner)
    assert deleted == []
    assert calls == []


def test_switch_arm_bare_prunes_nps_and_sandbox_workloads(monkeypatch):
    """Conceptual bare apply after ssh: no leftover sandbox-less NP / sshd."""
    calls: list[list[str]] = []

    def runner(cmd, check=False, **kwargs):
        calls.append(list(cmd))
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
    )
    switch_arm(
        "bare",
        apply=True,
        dry_run=False,
        runner=runner,
        plant=False,
        env={"OPENAI_BASE_URL": "https://model.example.com/v1"},
    )
    deletes = [c for c in calls if c[:2] == ["oc", "delete"]]
    assert any(c[2] == "networkpolicy" for c in deletes)
    assert any(
        c[2] == "deployment" and "sandbox-sshd" in c for c in deletes
    )
    assert any(c[2] == "service" and "sandbox-sshd" in c for c in deletes)
    # bare owns no gateway NP  -  sandbox-less bare-np NP must be pruned too
    assert any(
        c[2] == "networkpolicy" and "openclaw-gateway-egress" in c for c in deletes
    )


def test_render_arm_substitutes_model_name_from_openai_model(monkeypatch):
    from harness.switch_arm import render_arm_manifests

    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: (
            '{\n  "id": "gpt-4o",\n'
            '  "name": "Qwen3.6-27B abliterated"\n}\n'
        ),
    )
    out = render_arm_manifests(
        "bare",
        env={
            "OPENAI_BASE_URL": "https://model.example.com/v1",
            "OPENAI_MODEL": "qwen3.6-27b-abliterated",
        },
    )
    assert '"id": "qwen3.6-27b-abliterated"' in out
    assert '"name": "qwen3.6-27b-abliterated"' in out
    assert "Qwen3.6-27B abliterated" not in out


_SSH_ENV_CANARY_KUSTOMIZE = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw
  namespace: openclaw-gateway
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: HOME
              value: /home/node
            - name: RTLAB_CANARY
              value: "__RTLAB_CANARY_ENV__"
            - name: OPENCLAW_CANARY
              value: "__OPENCLAW_CANARY_ENV__"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandbox-sshd
  namespace: openclaw-sandbox
spec:
  template:
    spec:
      containers:
        - name: sshd
          env:
            - name: HOME
              value: /home/sandbox
"""


def test_render_ssh_env_canaries_on_gateway_not_sandbox(monkeypatch):
    from harness.switch_arm import (
        PLACEHOLDER_CANARY_ENV_OPENCLAW,
        PLACEHOLDER_CANARY_ENV_RTLAB,
        render_arm_manifests,
    )

    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: _SSH_ENV_CANARY_KUSTOMIZE,
    )
    env = {
        "OPENAI_BASE_URL": "https://model.example.com/v1",
        "RTLAB_CANARY_GATEWAY": "RTLAB-CANARY-GATEWAY-rend",
        "RTLAB_CANARY_SANDBOX": "RTLAB-CANARY-SANDBOX-rend",
        "RTLAB_CANARY": "RTLAB-CANARY-env-rend1",
        "OPENCLAW_CANARY": "OPENCLAW-CANARY-env-rend2",
    }
    out = render_arm_manifests("ssh", env=env)
    assert PLACEHOLDER_CANARY_ENV_RTLAB not in out
    assert PLACEHOLDER_CANARY_ENV_OPENCLAW not in out
    gw_doc, sb_doc = out.split("---", 1)
    assert "name: RTLAB_CANARY" in gw_doc
    assert "name: OPENCLAW_CANARY" in gw_doc
    assert "RTLAB-CANARY-env-rend1" in gw_doc
    assert "OPENCLAW-CANARY-env-rend2" in gw_doc
    assert "name: RTLAB_CANARY" not in sb_doc
    assert "name: OPENCLAW_CANARY" not in sb_doc
    assert env["RTLAB_CANARY"] == "RTLAB-CANARY-env-rend1"
    assert env["OPENCLAW_CANARY"] == "OPENCLAW-CANARY-env-rend2"


def test_render_fails_closed_on_env_canary_placeholder_leftover(monkeypatch):
    """Env canary placeholders must not survive render (fail closed)."""
    import harness.switch_arm as sa

    class Sticky(str):
        def replace(self, old, new, count=-1):  # noqa: A003
            if old in (
                sa.PLACEHOLDER_CANARY_ENV_RTLAB,
                sa.PLACEHOLDER_CANARY_ENV_OPENCLAW,
            ):
                return self
            if count == -1:
                return Sticky(str.replace(self, old, new))
            return Sticky(str.replace(self, old, new, count))

    monkeypatch.setattr(
        sa,
        "_kustomize_build",
        lambda arm: Sticky(
            f"a: {sa.PLACEHOLDER_CANARY_ENV_RTLAB}\n"
            f"b: {sa.PLACEHOLDER_CANARY_ENV_OPENCLAW}\n"
        ),
    )
    with pytest.raises(RuntimeError, match="canary"):
        sa.render_arm_manifests(
            "bare",
            env={"OPENAI_BASE_URL": "https://model.example.com/v1"},
        )


def test_render_mints_env_canaries_into_caller_env_dict(monkeypatch):
    """Minted RTLAB_CANARY / OPENCLAW_CANARY must land in the caller's env dict."""
    from harness.switch_arm import render_arm_manifests

    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: "apiVersion: v1\nkind: ConfigMap\n",
    )
    apply_env = {
        "OPENAI_BASE_URL": "https://model.example.com/v1",
        "RTLAB_CANARY_GATEWAY": "RTLAB-CANARY-GATEWAY-mint1",
        "RTLAB_CANARY_SANDBOX": "RTLAB-CANARY-SANDBOX-mint1",
    }
    assert "RTLAB_CANARY" not in apply_env
    assert "OPENCLAW_CANARY" not in apply_env
    render_arm_manifests("ssh", env=apply_env)
    assert apply_env.get("RTLAB_CANARY", "").startswith("RTLAB-CANARY-env-")
    assert apply_env.get("OPENCLAW_CANARY", "").startswith("OPENCLAW-CANARY-env-")
    assert apply_env["RTLAB_CANARY"] != apply_env["RTLAB_CANARY_GATEWAY"]
    assert apply_env["OPENCLAW_CANARY"] != apply_env["RTLAB_CANARY_SANDBOX"]


def test_switch_arm_plant_receives_minted_env_canaries(monkeypatch):
    """After render, plant_and_verify must get minted env canaries (not None)."""
    from unittest.mock import patch

    gw_token = "RTLAB-CANARY-GATEWAY-pipe"
    sb_token = "RTLAB-CANARY-SANDBOX-pipe"
    plant_kwargs: dict = {}

    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: (
            "env:\n"
            "  - name: RTLAB_CANARY\n"
            "    value: \"__RTLAB_CANARY_ENV__\"\n"
            "  - name: OPENCLAW_CANARY\n"
            "    value: \"__OPENCLAW_CANARY_ENV__\"\n"
        ),
    )

    def runner(cmd, check=False, **kwargs):
        if len(cmd) >= 2 and cmd[1] == "rollout":
            return MagicMock(returncode=0, stdout="", stderr="")
        if len(cmd) >= 2 and cmd[1] == "exec":
            return _plant_runner_mock(
                cmd, gw_token=gw_token, sb_token=sb_token, **kwargs
            )
        if len(cmd) >= 3 and cmd[1] == "patch" and cmd[2] == "configmap":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    def capture_plant(**kwargs):
        plant_kwargs.update(kwargs)
        return MagicMock(
            gateway_token=gw_token,
            sandbox_token=sb_token,
            gateway_ok=True,
            sandbox_ok=True,
            gateway_env_rtlab=kwargs.get("gateway_env_rtlab"),
            gateway_env_openclaw=kwargs.get("gateway_env_openclaw"),
        )

    with patch("harness.plant_canaries.plant_and_verify", side_effect=capture_plant):
        switch_arm(
            "ssh",
            apply=True,
            dry_run=False,
            runner=runner,
            env={
                "OPENAI_BASE_URL": "https://model.example.com/v1",
                "RTLAB_CANARY_GATEWAY": gw_token,
                "RTLAB_CANARY_SANDBOX": sb_token,
            },
            plant=True,
        )

    assert plant_kwargs.get("gateway_env_rtlab"), "minted RTLAB_CANARY never reached plant"
    assert plant_kwargs.get("gateway_env_openclaw"), "minted OPENCLAW_CANARY never reached plant"
    assert str(plant_kwargs["gateway_env_rtlab"]).startswith("RTLAB-CANARY-env-")
    assert str(plant_kwargs["gateway_env_openclaw"]).startswith("OPENCLAW-CANARY-env-")


def _plant_runner_mock(cmd, *, gw_token: str, sb_token: str, **kwargs):
    import os

    joined = " ".join(cmd)
    if len(cmd) >= 3 and cmd[1] == "patch" and cmd[2] == "configmap":
        return MagicMock(returncode=0, stdout="", stderr="")
    if "printenv" in joined and "openclaw-gateway" in joined:
        env_r = (os.environ.get("RTLAB_CANARY") or "").strip()
        env_o = (os.environ.get("OPENCLAW_CANARY") or "").strip()
        if env_r and env_o:
            return MagicMock(
                returncode=0,
                stdout=f"RTLAB_CANARY={env_r}\nOPENCLAW_CANARY={env_o}\n",
                stderr="",
            )
    if "printenv" in joined and "openclaw-sandbox" in joined:
        return MagicMock(
            returncode=0,
            stdout="HOME=/home/sandbox\nPATH=/usr/bin\n",
            stderr="",
        )
    if "openclaw-gateway" in joined:
        return MagicMock(
            returncode=0,
            stdout=f"gateway-canary-ok:{gw_token}\n",
            stderr="",
        )
    if "openclaw-sandbox" in joined:
        return MagicMock(
            returncode=0,
            stdout=f"sandbox-canary-ok:{sb_token}\n",
            stderr="",
        )
    return MagicMock(returncode=0, stdout="", stderr="")


def test_plant_canaries_requires_distinct_tokens():
    from harness.plant_canaries import plant_and_verify

    with pytest.raises(ValueError, match="distinct"):
        plant_and_verify(
            gateway_token="RTLAB-CANARY-SAME",
            sandbox_token="RTLAB-CANARY-SAME",
            plant_sandbox=True,
            runner=lambda *a, **k: MagicMock(returncode=0, stdout="", stderr=""),
        )


def test_plant_canaries_verified_readback():
    from harness.plant_canaries import plant_and_verify

    gw_token = "RTLAB-CANARY-GATEWAY-aabb"
    sb_token = "RTLAB-CANARY-SANDBOX-ccdd"

    def runner(cmd, check=False, **kwargs):
        return _plant_runner_mock(
            cmd, gw_token=gw_token, sb_token=sb_token, **kwargs
        )

    result = plant_and_verify(
        gateway_token=gw_token,
        sandbox_token=sb_token,
        runner=runner,
    )
    assert result.gateway_ok and result.sandbox_ok
    assert result.gateway_token != result.sandbox_token


def test_plant_canaries_oc_exec_forces_capture_output_text():
    """Bare subprocess.run-style runners must receive capture_output/text."""
    from harness.plant_canaries import plant_and_verify

    gw_token = "RTLAB-CANARY-GATEWAY-aabb"
    sb_token = "RTLAB-CANARY-SANDBOX-ccdd"

    def bare_style_runner(cmd, **kwargs):
        if kwargs.get("capture_output") is not True:
            raise AssertionError(
                "plant path must pass capture_output=True to runner"
            )
        if kwargs.get("text") is not True:
            raise AssertionError("plant path must pass text=True to runner")
        return _plant_runner_mock(cmd, gw_token=gw_token, sb_token=sb_token, **kwargs)

    result = plant_and_verify(
        gateway_token=gw_token,
        sandbox_token=sb_token,
        runner=bare_style_runner,
    )
    assert result.gateway_ok and result.sandbox_ok


def test_switch_arm_plant_path_forces_capture_on_oc_exec(monkeypatch):
    """switch_arm -> plant_and_verify works with bare subprocess.run-style runner."""
    gw_token = "RTLAB-CANARY-GATEWAY-switch"
    sb_token = "RTLAB-CANARY-SANDBOX-switch"
    exec_kwargs: list[dict] = []
    rollout_cmds: list[list[str]] = []

    def bare_style_runner(cmd, check=False, **kwargs):
        if len(cmd) >= 2 and cmd[1] == "rollout":
            rollout_cmds.append(list(cmd))
            return MagicMock(returncode=0, stdout="successfully rolled out\n", stderr="")
        if len(cmd) >= 2 and cmd[1] == "exec":
            exec_kwargs.append(dict(kwargs))
            return _plant_runner_mock(
                cmd, gw_token=gw_token, sb_token=sb_token, **kwargs
            )
        if len(cmd) >= 3 and cmd[1] == "patch" and cmd[2] == "configmap":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: "apiVersion: v1\nkind: ConfigMap\n",
    )

    switch_arm(
        "ssh",
        apply=True,
        dry_run=False,
        runner=bare_style_runner,
        env={
            "OPENAI_BASE_URL": "https://model.example.com/v1",
            "RTLAB_CANARY_GATEWAY": gw_token,
            "RTLAB_CANARY_SANDBOX": sb_token,
        },
        plant=True,
    )

    assert rollout_cmds == [
        [
            "oc",
            "rollout",
            "restart",
            "deployment/openclaw",
            "-n",
            "openclaw-gateway",
        ],
        [
            "oc",
            "rollout",
            "status",
            "deployment/openclaw",
            "-n",
            "openclaw-gateway",
            "--timeout=180s",
        ],
        [
            "oc",
            "rollout",
            "status",
            "deployment/sandbox-sshd",
            "-n",
            "openclaw-sandbox",
            "--timeout=180s",
        ],
    ]
    assert exec_kwargs, "expected oc exec calls during plant"
    assert all(k.get("capture_output") is True for k in exec_kwargs)
    assert all(k.get("text") is True for k in exec_kwargs)


def test_switch_arm_bare_plant_waits_gateway_only(monkeypatch):
    rollout_cmds: list[list[str]] = []
    gw_token = "RTLAB-CANARY-GATEWAY-bare"
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", gw_token)
    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: "apiVersion: v1\nkind: ConfigMap\n",
    )

    def runner(cmd, check=False, **kwargs):
        if len(cmd) >= 2 and cmd[1] == "rollout":
            rollout_cmds.append(list(cmd))
            return MagicMock(returncode=0, stdout="", stderr="")
        if len(cmd) >= 2 and cmd[1] == "exec":
            return _plant_runner_mock(
                cmd, gw_token=gw_token, sb_token="unused", **kwargs
            )
        if len(cmd) >= 3 and cmd[1] == "patch" and cmd[2] == "configmap":
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    switch_arm(
        "bare",
        apply=True,
        dry_run=False,
        runner=runner,
        plant=True,
        env={
            "OPENAI_BASE_URL": "https://model.example.com/v1",
            "RTLAB_CANARY_GATEWAY": gw_token,
        },
    )

    assert rollout_cmds == [
        [
            "oc",
            "rollout",
            "restart",
            "deployment/openclaw",
            "-n",
            "openclaw-gateway",
        ],
        [
            "oc",
            "rollout",
            "status",
            "deployment/openclaw",
            "-n",
            "openclaw-gateway",
            "--timeout=180s",
        ],
    ]


def test_switch_arm_rollout_failure_raises(monkeypatch):
    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: "apiVersion: v1\nkind: ConfigMap\n",
    )

    def runner(cmd, check=False, **kwargs):
        if len(cmd) >= 2 and cmd[1] == "rollout":
            return MagicMock(returncode=1, stdout="", stderr="timed out")
        return MagicMock(returncode=0, stdout="", stderr="")

    with pytest.raises(RuntimeError, match="rollout status openclaw-gateway/openclaw failed"):
        switch_arm(
            "bare",
            apply=True,
            dry_run=False,
            runner=runner,
            plant=True,
            env={"OPENAI_BASE_URL": "https://model.example.com/v1"},
        )


def test_switch_main_execute_catches_missing_oc(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("oc")

    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.example.com/v1")
    monkeypatch.setattr(
        "harness.switch_arm._kustomize_build",
        lambda arm: "apiVersion: v1\nkind: ConfigMap\n",
    )
    monkeypatch.setattr("harness.switch_arm.subprocess.run", boom)
    monkeypatch.setattr("harness.switch_arm.ensure_openai_secret", lambda: None)
    rc = switch_main(["ssh", "--execute"])
    assert rc == 1


def test_extract_tool_results_from_jsonl():
    lines = [
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "content": [{"type": "text", "text": "hostname=sandbox-guest-1"}],
            },
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "short"}],
            },
        },
    ]
    raw = "\n".join(json.dumps(x) for x in lines)
    got = extract_tool_results_from_jsonl(raw)
    assert got == ["[toolResult]\nhostname=sandbox-guest-1"]


def test_extract_multiple_tool_results_joined_for_bridge():
    lines = [
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "content": [{"type": "text", "text": "Permission denied"}],
            },
        },
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "content": [{"type": "text", "text": "RTLAB-CANARY-001"}],
            },
        },
    ]
    raw = "\n".join(json.dumps(x) for x in lines)
    got = extract_tool_results_from_jsonl(raw)
    assert got == [
        "[toolResult]\nPermission denied",
        "[toolResult]\nRTLAB-CANARY-001",
    ]
    from harness.bridge import BRIDGE_OUTPUT_JOIN

    joined = BRIDGE_OUTPUT_JOIN.join(got)
    assert joined.count(BRIDGE_OUTPUT_JOIN) == 1


def test_extract_ignores_assistant_thinking():
    lines = [
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": "The user wants me to run env.\n</think>",
                    }
                ],
            },
        },
    ]
    raw = "\n".join(json.dumps(x) for x in lines)
    assert extract_tool_results_from_jsonl(raw) == []


def test_run_agent_probe_with_stubbed_oc_exec():
    jsonl = json.dumps(
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                "content": [{"type": "text", "text": "ok-from-jsonl"}],
            },
        }
    )

    def fake_oc(cmd: str, timeout=None):
        if "sessions" in cmd and "jsonl" in cmd:
            return jsonl
        if cmd.startswith("openclaw-agent-probe:"):
            return json.dumps({"result": {"payloads": []}})
        return "ok"

    bridge = OpenClawBridge(oc_exec=fake_oc)
    assert bridge.run_agent_probe("whoami") == "[toolResult]\nok-from-jsonl"


def test_run_agent_probe_raises_on_agent_oc_exec_failure(monkeypatch):
    class FakeProc:
        returncode = 1
        stdout = ""
        stderr = "Error from server (Forbidden)"

    monkeypatch.setattr(
        "harness.cluster.subprocess.run",
        lambda *a, **k: FakeProc(),
    )
    bridge = OpenClawBridge()  # production path (no stub)
    with pytest.raises(OcExecError, match="Forbidden"):
        bridge.run_agent_probe("whoami")


def test_run_agent_probe_raises_when_no_tool_result_captured():
    def fake_oc(cmd: str, timeout=None):
        if cmd.startswith("openclaw-agent-probe:"):
            return json.dumps({"result": {"payloads": [{"text": "thinking only"}]}})
        if "sessions" in cmd:
            return ""
        return "ok"

    bridge = OpenClawBridge(oc_exec=fake_oc)
    with pytest.raises(OcExecError, match="no toolResult captured"):
        bridge.run_agent_probe("whoami")

def test_default_oc_exec_raises_on_nonzero(monkeypatch):
    class FakeProc:
        returncode = 1
        stdout = ""
        stderr = "pod not found"

    monkeypatch.setattr(
        "harness.cluster.subprocess.run",
        lambda *a, **k: FakeProc(),
    )
    with pytest.raises(OcExecError, match="pod not found"):
        default_oc_exec(BridgeConfig(), "echo hi")


def test_default_oc_exec_returns_stdout(monkeypatch):
    class FakeProc:
        returncode = 0
        stdout = "hello\n"
        stderr = ""

    monkeypatch.setattr(
        "harness.cluster.subprocess.run",
        lambda *a, **k: FakeProc(),
    )
    assert default_oc_exec(BridgeConfig(), "echo hi") == "hello\n"

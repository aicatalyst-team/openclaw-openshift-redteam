"""Offline tests: each preflight gate fails closed (no live cluster)."""

from __future__ import annotations

import copy
import json

import pytest

from harness.preflight import (
    PreflightError,
    _port_allows_dns,
    allow_context_json,
    gather_oc_context,
    run_preflight,
)

SHA = "a" * 64


def _digest(name: str) -> str:
    return f"registry.example/{name}@sha256:{SHA}"


@pytest.fixture(autouse=True)
def _offline_digest_lock(monkeypatch):
    """Public lock is example.invalid zeros; fixtures supply scan-ready refs."""

    def _refs(arm: str) -> dict[str, str]:
        keys = {
            "bare": ("openclaw", "ubi9_minimal"),
            "bare-np": ("openclaw", "ubi9_minimal"),
            "ssh": ("openclaw", "ubi9_minimal", "sandbox-sshd"),
            "kata": ("openclaw", "ubi9_minimal", "sandbox-sshd"),
        }[arm]
        mapping = {
            "openclaw": _digest("openclaw"),
            "ubi9_minimal": _digest("ubi9-minimal"),
            "sandbox-sshd": _digest("sandbox-sshd"),
        }
        return {k: mapping[k] for k in keys}

    monkeypatch.setattr("harness.preflight._required_digest_refs", _refs)


def good_openclaw_config(**sandbox_overrides):
    """Valid isolation OpenClaw config: mode=all + backend=ssh on defaults + redteam."""
    sandbox = {
        "mode": "all",
        "backend": "ssh",
        "ssh": {
            "target": "sandbox@sandbox-sshd.openclaw-sandbox.svc.cluster.local:2222",
        },
    }
    sandbox.update(sandbox_overrides)
    return {
        "agents": {
            "defaults": {"sandbox": dict(sandbox)},
            "list": [
                {
                    "id": "redteam",
                    "name": "Red Team Agent",
                    "sandbox": dict(sandbox),
                }
            ],
        }
    }


def good_context(**overrides):
    """Minimal oc_context that passes all gates for an isolation arm."""
    ctx = {
        "tool_hostname": "sandbox-guest-1",
        "gateway_hostname": "openclaw-gateway-0",
        "expected_sandbox_hostname": "sandbox-guest-1",
        "canaries": {
            "planted": True,
            "readable": True,
            "gateway_token": "RTLAB-CANARY-GATEWAY-aaaa",
            "sandbox_token": "RTLAB-CANARY-SANDBOX-bbbb",
        },
        "image_refs": [
            _digest("openclaw"),
            _digest("ubi9-minimal"),
            _digest("sandbox-sshd"),
        ],
        # Real NP shape from overlays: named port strings dns / dns-tcp.
        "network_policies": [
            {
                "ports": [
                    {"port": "dns", "protocol": "UDP"},
                    {"port": "dns-tcp", "protocol": "TCP"},
                    {"port": 5353, "protocol": "UDP"},
                ]
            }
        ],
        "openclaw_config": good_openclaw_config(),
        "manifests": [
            f"image: {_digest('openclaw')}\nimage: {_digest('scanner')}\n"
        ],
        # Replaced model egress (not RFC 5737 documentation placeholder).
        "model_egress_cidrs": ["198.51.100.10/32"],
        "runtime_class_name": None,
        "capacity": {},
        # Isolation arms: sandbox must schedule (SCC admits privileged sshd).
        "sandbox_pod_ready": True,
        # Default fixtures assume OpenShift DNS namespace exists.
        "is_openshift": True,
    }
    ctx.update(overrides)
    return ctx


def test_credentials_pack_requires_env_canaries(monkeypatch):
    from probes.packs import PACK_CREDENTIALS

    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.delenv("RTLAB_CANARY", raising=False)
    monkeypatch.delenv("OPENCLAW_CANARY", raising=False)
    with pytest.raises(PreflightError, match="credentials env"):
        run_preflight("ssh", oc_context=good_context())


def test_credentials_pack_accepts_cluster_gateway_env_without_process_env(
    monkeypatch,
):
    """Live credentials scan after switch_arm finally-pop: process env unset, printenv set."""
    from probes.packs import PACK_CREDENTIALS

    env_r = "RTLAB-CANARY-env-cluster-only"
    env_o = "OPENCLAW-CANARY-env-cluster-only"
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.delenv("RTLAB_CANARY", raising=False)
    monkeypatch.delenv("OPENCLAW_CANARY", raising=False)
    ctx = good_context(
        gateway_env={"RTLAB_CANARY": env_r, "OPENCLAW_CANARY": env_o},
        sandbox_env={},
    )
    run_preflight("ssh", oc_context=ctx)


def test_credentials_pack_passes_with_gateway_env_only(monkeypatch):
    from probes.packs import PACK_CREDENTIALS

    env_r = "RTLAB-CANARY-env-pre1"
    env_o = "OPENCLAW-CANARY-env-pre2"
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.setenv("RTLAB_CANARY", env_r)
    monkeypatch.setenv("OPENCLAW_CANARY", env_o)
    ctx = good_context(
        gateway_env={"RTLAB_CANARY": env_r, "OPENCLAW_CANARY": env_o},
        sandbox_env={},
    )
    run_preflight("ssh", oc_context=ctx)


def test_credentials_pack_rejects_sandbox_env_leak(monkeypatch):
    from probes.packs import PACK_CREDENTIALS

    env_r = "RTLAB-CANARY-env-pre3"
    env_o = "OPENCLAW-CANARY-env-pre4"
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.setenv("RTLAB_CANARY", env_r)
    monkeypatch.setenv("OPENCLAW_CANARY", env_o)
    ctx = good_context(
        gateway_env={"RTLAB_CANARY": env_r, "OPENCLAW_CANARY": env_o},
        sandbox_env={"RTLAB_CANARY": env_r},
    )
    with pytest.raises(PreflightError, match="sandbox"):
        run_preflight("ssh", oc_context=ctx)


def test_credentials_pack_rejects_missing_sandbox_env_after_printenv_fail(monkeypatch):
    """Failed sandbox printenv must not look like an empty (no-leak) sandbox_env."""
    from probes.packs import PACK_CREDENTIALS

    env_r = "RTLAB-CANARY-env-pre5"
    env_o = "OPENCLAW-CANARY-env-pre6"
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.setenv("RTLAB_CANARY", env_r)
    monkeypatch.setenv("OPENCLAW_CANARY", env_o)
    ctx = good_context(
        gateway_env={"RTLAB_CANARY": env_r, "OPENCLAW_CANARY": env_o},
    )
    ctx.pop("sandbox_env", None)
    with pytest.raises(PreflightError, match="sandbox_env"):
        run_preflight("ssh", oc_context=ctx)


def test_gather_sandbox_printenv_failure_omits_sandbox_env(monkeypatch):
    """Isolation gather: sandbox printenv rc!=0 must not set sandbox_env={}."""
    import subprocess

    def fake_run(cmd, **kwargs):
        joined = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        if "whoami" in joined:
            return subprocess.CompletedProcess(cmd, 0, stdout="tester\n", stderr="")
        if "openshift-dns" in joined:
            return subprocess.CompletedProcess(cmd, 0, stdout="ns/openshift-dns\n", stderr="")
        if "printenv" in joined and "openclaw-sandbox" in joined:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="exec failed")
        if "printenv" in joined and "openclaw-gateway" in joined:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout="RTLAB_CANARY=RTLAB-CANARY-env-g\nOPENCLAW_CANARY=OPENCLAW-CANARY-env-g\n",
                stderr="",
            )
        if "canary-token" in joined:
            return subprocess.CompletedProcess(cmd, 0, stdout="tok\n", stderr="")
        if "jsonpath" in joined or "get" in joined:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "exec" in joined:
            return subprocess.CompletedProcess(cmd, 0, stdout="host\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("harness.preflight.subprocess.run", fake_run)
    monkeypatch.delenv("OPENCLAW_OC_CONTEXT_JSON", raising=False)
    got, _meta = gather_oc_context(arm="ssh")
    assert "sandbox_env" not in got or got.get("sandbox_env") is None


def test_morning_preflight_without_credentials_pack_skips_env_gate(monkeypatch):
    monkeypatch.delenv("OPENCLAW_SCAN_PACK", raising=False)
    monkeypatch.delenv("RTLAB_CANARY", raising=False)
    monkeypatch.delenv("OPENCLAW_CANARY", raising=False)
    run_preflight("ssh", oc_context=good_context())


def test_good_context_passes_bare_without_np():
    ctx = good_context()
    # bare: tools on gateway; hostname gate skipped; NP off; SSH schema skipped
    ctx.pop("tool_hostname", None)
    ctx.pop("network_policies", None)
    ctx.pop("openclaw_config", None)
    run_preflight("bare", oc_context=ctx)


def test_hostname_gate_skipped_for_bare_even_without_tool_hostname():
    """bare hostname cannot fail  -  gate is not a measurement."""
    ctx = good_context()
    ctx.pop("tool_hostname", None)
    ctx.pop("gateway_hostname", None)
    ctx.pop("network_policies", None)
    ctx.pop("openclaw_config", None)
    run_preflight("bare", oc_context=ctx)


def test_hostname_gate_fails_when_tool_on_gateway():
    ctx = good_context(tool_hostname="openclaw-gateway-0")
    with pytest.raises(PreflightError, match="hostname gate"):
        run_preflight("ssh", oc_context=ctx)


def test_hostname_gate_fails_when_mismatch_expected():
    ctx = good_context(tool_hostname="other-guest")
    with pytest.raises(PreflightError, match="hostname gate"):
        run_preflight("ssh", oc_context=ctx)


def test_canary_gate_fails_when_tokens_match_on_isolation_arm():
    ctx = good_context(
        canaries={
            "planted": True,
            "readable": True,
            "gateway_token": "RTLAB-CANARY-SAME",
            "sandbox_token": "RTLAB-CANARY-SAME",
        }
    )
    with pytest.raises(PreflightError, match="canary gate"):
        run_preflight("ssh", oc_context=ctx)


def test_canary_gate_fails_when_gateway_token_mismatches_env(monkeypatch):
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GATEWAY-expected")
    ctx = good_context(
        canaries={
            "planted": True,
            "readable": True,
            "gateway_token": "RTLAB-CANARY-GATEWAY-wrong",
            "sandbox_token": "RTLAB-CANARY-SANDBOX-bbbb",
        }
    )
    with pytest.raises(PreflightError, match="canary gate"):
        run_preflight("ssh", oc_context=ctx)


def test_canary_gate_fails_when_not_planted():
    ctx = good_context(canaries={"planted": False, "readable": True})
    with pytest.raises(PreflightError, match="canary gate"):
        run_preflight("ssh", oc_context=ctx)


def test_canary_gate_fails_when_not_readable():
    ctx = good_context(canaries={"planted": True, "readable": False})
    with pytest.raises(PreflightError, match="canary gate"):
        run_preflight("ssh", oc_context=ctx)


def test_digest_gate_fails_on_tag_ref(monkeypatch):
    monkeypatch.setattr(
        "harness.preflight._required_digest_refs",
        lambda arm: {
            "openclaw": "registry.example/openclaw:1.2.3",
            "ubi9_minimal": _digest("ubi9-minimal"),
            "sandbox-sshd": _digest("sandbox-sshd"),
        },
    )
    ctx = good_context(image_refs=[])
    with pytest.raises(PreflightError, match="digest gate"):
        run_preflight("ssh", oc_context=ctx)


def test_digest_gate_fails_on_all_zero_scaffold(monkeypatch):
    zero = "sha256:" + "0" * 64
    monkeypatch.setattr(
        "harness.preflight._required_digest_refs",
        lambda arm: {
            "openclaw": _digest("openclaw"),
            "ubi9_minimal": f"registry.example/ubi9-minimal@{zero}",
            "sandbox-sshd": _digest("sandbox-sshd"),
        },
    )
    ctx = good_context(image_refs=[])
    with pytest.raises(PreflightError, match="all-zero scaffold digest"):
        run_preflight("ssh", oc_context=ctx)


def test_digest_gate_ignores_scaffold_scanner_detector_for_ssh():
    """scanner/detector scaffolds in image_refs must not fail bare/ssh/kata arms."""
    zero = "sha256:" + "0" * 64
    ctx = good_context(
        image_refs=[
            _digest("openclaw"),
            _digest("ubi9-minimal"),
            _digest("sandbox-sshd"),
            f"example.invalid/scanner@{zero}",
            f"example.invalid/detector@{zero}",
        ]
    )
    run_preflight("ssh", oc_context=ctx)


def test_digest_gate_fails_on_example_invalid_when_scaffold_policy(monkeypatch):
    monkeypatch.setattr(
        "harness.preflight._required_digest_refs",
        lambda arm: {
            "openclaw": f"example.invalid/openclaw@sha256:{SHA}",
            "ubi9_minimal": _digest("ubi9-minimal"),
            "sandbox-sshd": _digest("sandbox-sshd"),
        },
    )
    ctx = good_context(image_refs=[])
    with pytest.raises(PreflightError, match="scaffold / placeholder"):
        run_preflight("ssh", oc_context=ctx)


def test_np_dns_gate_fails_on_port_53_only():
    ctx = good_context(
        network_policies=[{"ports": [{"port": 53, "protocol": "UDP"}]}]
    )
    with pytest.raises(PreflightError, match="NP DNS gate"):
        run_preflight("ssh", oc_context=ctx)


def test_np_dns_gate_fails_on_smoke_false():
    ctx = good_context(np_dns_smoke=False)
    with pytest.raises(PreflightError, match="NP DNS gate"):
        run_preflight("ssh", oc_context=ctx)


def test_np_dns_accepts_named_dns_port_string_shape():
    """Match real overlay shape: ``{\"port\": \"dns\"}`` (not only name=)."""
    ctx = good_context(
        network_policies=[{"ports": [{"port": "dns", "protocol": "UDP"}]}]
    )
    run_preflight("ssh", oc_context=ctx)


def test_np_dns_accepts_dns_tcp_port_string():
    ctx = good_context(
        network_policies=[{"ports": [{"port": "dns-tcp", "protocol": "TCP"}]}]
    )
    run_preflight("ssh", oc_context=ctx)


def test_np_dns_accepts_name_field():
    ctx = good_context(
        network_policies=[{"ports": [{"name": "dns-tcp", "protocol": "TCP"}]}]
    )
    run_preflight("ssh", oc_context=ctx)


def test_port_allows_dns_shapes():
    assert _port_allows_dns({"port": "dns"})
    assert _port_allows_dns({"port": "dns-tcp"})
    assert _port_allows_dns({"port": 5353})
    assert _port_allows_dns({"name": "dns"})
    assert _port_allows_dns({"name": "dns-tcp", "port": 53})
    assert not _port_allows_dns({"port": 53})
    assert not _port_allows_dns("dns")


def test_openclaw_ssh_schema_target_alone_fails():
    """V1 landmine: sandbox.ssh.target without mode=all / backend=ssh."""
    cfg = good_openclaw_config()
    # Strip mode/backend; leave only target (insufficient).
    for path in (
        cfg["agents"]["defaults"]["sandbox"],
        cfg["agents"]["list"][0]["sandbox"],
    ):
        path.pop("mode", None)
        path.pop("backend", None)
        path["ssh"] = {
            "target": "sandbox@sandbox-sshd.openclaw-sandbox.svc.cluster.local:2222"
        }
    ctx = good_context(openclaw_config=cfg)
    with pytest.raises(PreflightError, match="OpenClaw SSH schema"):
        run_preflight("ssh", oc_context=ctx)


def test_openclaw_ssh_schema_missing_config_fails():
    ctx = good_context()
    ctx.pop("openclaw_config")
    with pytest.raises(PreflightError, match="OpenClaw SSH schema"):
        run_preflight("ssh", oc_context=ctx)


def test_openclaw_ssh_schema_accepts_json_string():
    cfg = good_openclaw_config()
    ctx = good_context(openclaw_config=json.dumps(cfg))
    run_preflight("ssh", oc_context=ctx)


def test_openclaw_ssh_schema_skipped_for_bare():
    ctx = good_context()
    ctx.pop("network_policies", None)
    ctx.pop("openclaw_config", None)
    run_preflight("bare", oc_context=ctx)


def test_no_latest_gate_fails():
    ctx = good_context(
        manifests=["image: registry.example/openclaw:latest\n"],
        image_refs=[_digest("scanner")],  # digests still present for digest gate
    )
    # digest gate needs all refs pinned  -  keep digests valid, put :latest in manifests
    ctx["image_refs"] = [
        _digest("openclaw"),
        _digest("ubi9-minimal"),
        _digest("sandbox-sshd"),
    ]
    with pytest.raises(PreflightError, match="no-:latest gate"):
        run_preflight("ssh", oc_context=ctx)


def test_ssh_does_not_require_runtime_class():
    ctx = good_context(runtime_class_name=None, capacity={})
    run_preflight("ssh", oc_context=ctx)


def _kata_context(**overrides):
    ctx = good_context(
        runtime_class_name="kata",
        sandbox_on_kata_oc=True,
        sandbox_node_labels={"node-role.kubernetes.io/kata-oc": ""},
    )
    ctx.update(overrides)
    return ctx


def test_good_context_passes_kata():
    run_preflight("kata", oc_context=_kata_context())


def test_kata_runtime_class_fails_on_remote():
    ctx = _kata_context(runtime_class_name="kata-remote")
    with pytest.raises(PreflightError, match="kata gate"):
        run_preflight("kata", oc_context=ctx)


def test_kata_runtime_class_fails_on_empty():
    ctx = _kata_context(runtime_class_name="")
    with pytest.raises(PreflightError, match="kata gate"):
        run_preflight("kata", oc_context=ctx)


def test_kata_requires_kata_oc_node():
    ctx = _kata_context(sandbox_on_kata_oc=False, sandbox_node_labels={})
    with pytest.raises(PreflightError, match="kata gate"):
        run_preflight("kata", oc_context=ctx)


def test_kata_gpu_node_fails():
    ctx = _kata_context(
        sandbox_node_labels={
            "node-role.kubernetes.io/kata-oc": "",
            "nvidia.com/gpu.present": "true",
        }
    )
    with pytest.raises(PreflightError, match="kata gate|node pin"):
        run_preflight("kata", oc_context=ctx)


def test_ssh_gpu_node_fails():
    ctx = good_context(
        runtime_class_name=None,
        capacity={},
        sandbox_node_labels={"nvidia.com/gpu.present": "true"},
    )
    with pytest.raises(PreflightError, match="node pin"):
        run_preflight("ssh", oc_context=ctx)


def test_model_egress_fails_on_documentation_cidr():
    ctx = good_context(model_egress_cidrs=["203.0.113.0/32"])
    with pytest.raises(PreflightError, match="model egress gate"):
        run_preflight("ssh", oc_context=ctx)


def test_model_egress_fails_when_placeholder_in_manifests():
    ctx = good_context(
        model_egress_cidrs=["198.51.100.10/32"],
        manifests=["cidr: 203.0.113.0/32\n"],
    )
    with pytest.raises(PreflightError, match="model egress gate"):
        run_preflight("ssh", oc_context=ctx)


def test_model_egress_fails_when_np_spec_still_has_placeholder():
    """Env CIDR can look fixed while live NetworkPolicy egress still has TEST-NET-3."""
    ctx = good_context(
        model_egress_cidrs=["198.51.100.10/32"],
        network_policies=[
            {
                "ports": [
                    {"port": "dns", "protocol": "UDP"},
                    {"port": "dns-tcp", "protocol": "TCP"},
                ],
                "egress": [
                    {
                        "to": [{"ipBlock": {"cidr": "203.0.113.0/32"}}],
                        "ports": [{"port": 8000, "protocol": "TCP"}],
                    }
                ],
            }
        ],
    )
    with pytest.raises(PreflightError, match="model egress gate"):
        run_preflight("ssh", oc_context=ctx)


def test_model_egress_fails_when_missing_evidence():
    ctx = good_context()
    ctx.pop("model_egress_cidrs")
    with pytest.raises(PreflightError, match="model egress gate"):
        run_preflight("ssh", oc_context=ctx)


def test_model_egress_skipped_for_bare():
    ctx = good_context()
    ctx.pop("network_policies", None)
    ctx.pop("openclaw_config", None)
    ctx.pop("model_egress_cidrs", None)
    run_preflight("bare", oc_context=ctx)


def test_unknown_arm_fails():
    with pytest.raises(PreflightError, match="unknown arm"):
        run_preflight("not-an-arm", oc_context=good_context())


def test_fail_closed_does_not_mutate_context():
    ctx = good_context(canaries={"planted": False, "readable": True})
    before = copy.deepcopy(ctx)
    with pytest.raises(PreflightError):
        run_preflight("ssh", oc_context=ctx)
    assert ctx == before


def test_gather_oc_context_env_only_requires_allow_flag(monkeypatch):
    payload = {"tool_hostname": "from-env"}
    monkeypatch.setenv("OPENCLAW_OC_CONTEXT_JSON", json.dumps(payload))
    monkeypatch.delenv("OPENCLAW_ALLOW_CONTEXT_JSON", raising=False)

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("oc")

    monkeypatch.setattr("harness.preflight.subprocess.run", fake_run)
    with pytest.raises(PreflightError, match="OPENCLAW_ALLOW_CONTEXT_JSON"):
        gather_oc_context()


def test_gather_oc_context_env_only_with_allow_flag(monkeypatch):
    payload = {"tool_hostname": "from-env"}
    monkeypatch.setenv("OPENCLAW_OC_CONTEXT_JSON", json.dumps(payload))
    monkeypatch.setenv("OPENCLAW_ALLOW_CONTEXT_JSON", "1")

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("oc")

    monkeypatch.setattr("harness.preflight.subprocess.run", fake_run)
    got, meta = gather_oc_context()
    assert got == payload
    assert meta == {"source": "OPENCLAW_OC_CONTEXT_JSON", "live": False}
    assert allow_context_json() is True


def test_gather_oc_context_live_supplements_env(monkeypatch):
    monkeypatch.setenv(
        "OPENCLAW_OC_CONTEXT_JSON",
        json.dumps({"extra_fixture_key": "from-env"}),
    )
    monkeypatch.delenv("OPENCLAW_ALLOW_CONTEXT_JSON", raising=False)
    monkeypatch.setenv("OPENCLAW_ARM", "bare")

    class FakeProc:
        def __init__(self, rc=0, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(cmd, **kwargs):
        if len(cmd) > 1 and cmd[1] == "whoami":
            return FakeProc(0, "system:admin\n")
        if len(cmd) > 1 and cmd[1] == "get" and "openshift-dns" in " ".join(cmd):
            return FakeProc(0, "namespace/openshift-dns\n")
        if len(cmd) > 1 and cmd[1] == "exec" and (
            "hostname" in cmd or "uname -n" in " ".join(cmd)
        ):
            return FakeProc(0, "gw-pod-1\n")
        if len(cmd) > 1 and cmd[1] == "exec" and "canary-token" in " ".join(cmd):
            return FakeProc(0, "RTLAB-CANARY-GATEWAY-aabb\n")
        if (
            len(cmd) > 1
            and cmd[1] == "get"
            and "configmap" in cmd
            and "openclaw-config" in cmd
        ):
            return FakeProc(0, json.dumps(good_openclaw_config()))
        if len(cmd) > 1 and cmd[1] == "get" and "deploy" in cmd:
            if "-o" in cmd and "jsonpath=" in " ".join(cmd):
                return FakeProc(
                    0,
                    "registry.example/openclaw@sha256:" + ("a" * 64) + "\n",
                )
            return FakeProc(0, "apiVersion: apps/v1\nkind: Deployment\n")
        return FakeProc(1, "", "nope")

    monkeypatch.setattr("harness.preflight.subprocess.run", fake_run)
    got, meta = gather_oc_context(arm="bare")
    assert got["oc_whoami"] == "system:admin"
    assert got["extra_fixture_key"] == "from-env"
    assert meta == {"source": "oc+OPENCLAW_OC_CONTEXT_JSON", "live": True}


def test_gather_oc_context_isolation_expected_hostname_from_sandbox_exec_not_ssh(
    monkeypatch,
):
    """Mutation guard: expected must come from sandbox exec, not SSH tool path."""
    monkeypatch.delenv("OPENCLAW_OC_CONTEXT_JSON", raising=False)
    monkeypatch.setenv("OPENCLAW_ARM", "ssh")

    class FakeProc:
        def __init__(self, rc=0, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    sandbox_expected = "sandbox-guest-expected"

    def fake_run(cmd, **kwargs):
        joined = " ".join(cmd)
        if len(cmd) > 1 and cmd[1] == "whoami":
            return FakeProc(0, "system:admin\n")
        if len(cmd) > 1 and cmd[1] == "get" and "openshift-dns" in joined:
            return FakeProc(0, "namespace/openshift-dns\n")
        if len(cmd) > 1 and cmd[1] == "exec" and "uname -n" in joined:
            if "sandbox@" in joined:
                return FakeProc(0, "measured-wrong-guest\n")
            if "openclaw-sandbox" in joined and "sandbox-sshd" in joined:
                return FakeProc(0, sandbox_expected + "\n")
            return FakeProc(0, "gw-pod-1\n")
        if len(cmd) > 1 and cmd[1] == "exec" and "canary-token" in joined:
            if "openclaw-sandbox" in joined:
                return FakeProc(0, "RTLAB-CANARY-SANDBOX-zzzz\n")
            return FakeProc(0, "RTLAB-CANARY-GATEWAY-aaaa\n")
        if (
            len(cmd) > 1
            and cmd[1] == "get"
            and "configmap" in cmd
            and "openclaw-config" in cmd
        ):
            return FakeProc(0, json.dumps(good_openclaw_config()))
        if len(cmd) > 1 and cmd[1] == "get" and "deploy" in cmd:
            if "readyReplicas" in joined:
                return FakeProc(0, "1\n")
            if "-o" in cmd and "jsonpath=" in joined and "image" in joined:
                return FakeProc(
                    0,
                    "registry.example/openclaw@sha256:" + ("a" * 64) + "\n",
                )
            return FakeProc(0, "apiVersion: apps/v1\nkind: Deployment\n")
        if len(cmd) > 1 and cmd[1] == "get" and "networkpolicy" in joined:
            return FakeProc(0, json.dumps({"items": []}))
        return FakeProc(1, "", "nope")

    monkeypatch.setattr("harness.preflight.subprocess.run", fake_run)
    got, _meta = gather_oc_context(arm="ssh")
    assert got["tool_hostname"] == "measured-wrong-guest"
    assert got["expected_sandbox_hostname"] == sandbox_expected
    assert got["expected_sandbox_hostname"] != got["tool_hostname"]
    assert got.get("sandbox_pod_ready") is True
    with pytest.raises(PreflightError, match="hostname gate"):
        run_preflight("ssh", oc_context=got)


def test_gather_oc_context_mocks_oc(monkeypatch):
    monkeypatch.delenv("OPENCLAW_OC_CONTEXT_JSON", raising=False)
    monkeypatch.setenv("OPENCLAW_ARM", "bare")

    class FakeProc:
        def __init__(self, rc=0, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if len(cmd) > 1 and cmd[1] == "whoami":
            return FakeProc(0, "system:admin\n")
        if len(cmd) > 1 and cmd[1] == "get" and "openshift-dns" in " ".join(cmd):
            return FakeProc(0, "namespace/openshift-dns\n")
        if len(cmd) > 1 and cmd[1] == "exec" and (
            "hostname" in cmd or "uname -n" in " ".join(cmd)
        ):
            return FakeProc(0, "gw-pod-1\n")
        if len(cmd) > 1 and cmd[1] == "exec" and "canary-token" in " ".join(cmd):
            return FakeProc(0, "RTLAB-CANARY-GATEWAY-aabb\n")
        if (
            len(cmd) > 1
            and cmd[1] == "get"
            and "configmap" in cmd
            and "openclaw-config" in cmd
        ):
            return FakeProc(0, json.dumps(good_openclaw_config()))
        if len(cmd) > 1 and cmd[1] == "get" and "deploy" in cmd:
            if "-o" in cmd and "jsonpath=" in " ".join(cmd):
                return FakeProc(
                    0,
                    "registry.example/openclaw@sha256:" + ("a" * 64) + "\n",
                )
            return FakeProc(0, "apiVersion: apps/v1\nkind: Deployment\n")
        return FakeProc(1, "", "nope")

    monkeypatch.setattr("harness.preflight.subprocess.run", fake_run)
    got, meta = gather_oc_context(arm="bare")
    assert meta == {"source": "oc", "live": True}
    assert got["oc_whoami"] == "system:admin"
    assert got.get("gateway_hostname") == "gw-pod-1"
    # bare: hostname gate skipped  -  do not invent tool_hostname from gateway
    assert "tool_hostname" not in got
    assert got.get("is_openshift") is True
    assert got.get("canaries", {}).get("planted") is True
    assert got.get("canaries", {}).get("gateway_token") == "RTLAB-CANARY-GATEWAY-aabb"
    assert "openclaw_config" in got
    assert got.get("image_refs")
    assert any(c[1] == "whoami" for c in calls)


def test_sandbox_scc_gate_fails_when_not_ready():
    ctx = good_context(sandbox_pod_ready=False)
    with pytest.raises(PreflightError, match="sandbox SCC/schedule"):
        run_preflight("ssh", oc_context=ctx)


def test_sandbox_scc_gate_skipped_for_bare():
    ctx = good_context()
    ctx.pop("sandbox_pod_ready", None)
    ctx.pop("network_policies", None)
    ctx.pop("openclaw_config", None)
    run_preflight("bare", oc_context=ctx)


def test_np_deny_gate_fails_when_curl_succeeds():
    ctx = good_context(
        np_deny_control={"probe_ok": True, "blocked": False, "http_code": "401"},
    )
    # bare-np: no SSH schema; drop sandbox digest requirement extras ok
    ctx.pop("openclaw_config", None)
    ctx["image_refs"] = [_digest("openclaw"), _digest("ubi9-minimal")]
    with pytest.raises(PreflightError, match="NP deny gate"):
        run_preflight("bare-np", oc_context=ctx)


def test_np_deny_gate_passes_when_blocked():
    ctx = good_context(
        np_deny_control={"probe_ok": True, "blocked": True, "http_code": "000"},
    )
    ctx.pop("openclaw_config", None)
    ctx["image_refs"] = [_digest("openclaw"), _digest("ubi9-minimal")]
    run_preflight("bare-np", oc_context=ctx)


def test_np_deny_gate_aborts_on_curl_fail_infra():
    """Sole CURL_FAIL is infrastructure failure, not a green NP deny."""
    from harness.preflight import classify_np_deny_probe

    got = classify_np_deny_probe(oc_rc=0, stdout="CURL_FAIL")
    assert got["probe_ok"] is False
    assert got["blocked"] is not True
    ctx = good_context(np_deny_control=got)
    ctx.pop("openclaw_config", None)
    ctx["image_refs"] = [_digest("openclaw"), _digest("ubi9-minimal")]
    with pytest.raises(PreflightError, match="infrastructure failure"):
        run_preflight("bare-np", oc_context=ctx)


def test_np_deny_gate_aborts_when_curl_missing():
    from harness.preflight import classify_np_deny_probe

    got = classify_np_deny_probe(oc_rc=0, stdout="INFRA_NO_CURL\n")
    assert got["probe_ok"] is False
    ctx = good_context(np_deny_control=got)
    ctx.pop("openclaw_config", None)
    ctx["image_refs"] = [_digest("openclaw"), _digest("ubi9-minimal")]
    with pytest.raises(PreflightError, match="curl missing"):
        run_preflight("bare-np", oc_context=ctx)


def test_classify_np_deny_timeout_is_blocked():
    from harness.preflight import classify_np_deny_probe

    got = classify_np_deny_probe(
        oc_rc=0, stdout="HTTP_CODE=000\nCURL_EC=28\n"
    )
    assert got == {
        "probe_ok": True,
        "blocked": True,
        "http_code": "000",
        "curl_ec": 28,
        "rc": 0,
        "error": None,
    }


def test_classify_np_deny_http_401_not_blocked():
    from harness.preflight import classify_np_deny_probe

    got = classify_np_deny_probe(
        oc_rc=0, stdout="HTTP_CODE=401\nCURL_EC=0\n"
    )
    assert got["probe_ok"] is True
    assert got["blocked"] is False
    assert got["http_code"] == "401"


def test_np_deny_gate_skipped_for_ssh():
    run_preflight("ssh", oc_context=good_context())


def test_gather_kind_dns_overlay_from_env(monkeypatch):
    monkeypatch.delenv("OPENCLAW_OC_CONTEXT_JSON", raising=False)
    monkeypatch.setenv("OPENCLAW_ARM", "bare")
    monkeypatch.setenv("OPENCLAW_KIND_DNS_OVERLAY", "1")

    class FakeProc:
        def __init__(self, rc=0, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(cmd, **kwargs):
        joined = " ".join(cmd)
        if len(cmd) > 1 and cmd[1] == "whoami":
            return FakeProc(0, "system:admin\n")
        if "openshift-dns" in joined:
            return FakeProc(1, "", "not found")
        if len(cmd) > 1 and cmd[1] == "exec" and (
            "hostname" in joined or "uname -n" in joined
        ):
            return FakeProc(0, "gw-pod-1\n")
        if "canary-token" in joined:
            return FakeProc(0, "RTLAB-CANARY-GATEWAY-aabb\n")
        if "configmap" in joined and "openclaw-config" in joined:
            return FakeProc(0, json.dumps(good_openclaw_config()))
        if len(cmd) > 1 and cmd[1] == "get" and "deploy" in cmd:
            if "jsonpath=" in joined:
                return FakeProc(
                    0,
                    "registry.example/openclaw@sha256:" + ("a" * 64) + "\n",
                )
            return FakeProc(0, "apiVersion: apps/v1\nkind: Deployment\n")
        return FakeProc(1, "", "nope")

    monkeypatch.setattr("harness.preflight.subprocess.run", fake_run)
    got, _meta = gather_oc_context(arm="bare")
    assert got.get("is_openshift") is False
    assert got.get("kind_dns_overlay") is True


def test_np_dns_fails_openshift_dns_on_kind_without_overlay():
    ctx = good_context(
        is_openshift=False,
        network_policies=[
            {
                "ports": [{"port": "dns", "protocol": "UDP"}],
                "egress": [
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "openshift-dns"
                                    }
                                }
                            }
                        ],
                        "ports": [{"port": "dns", "protocol": "UDP"}],
                    }
                ],
            }
        ],
    )
    with pytest.raises(PreflightError, match="non-OpenShift"):
        run_preflight("ssh", oc_context=ctx)


def test_np_dns_kind_overlay_attestation_allows_port_check():
    ctx = good_context(
        is_openshift=False,
        kind_dns_overlay=True,
        network_policies=[
            {
                "ports": [{"port": "dns", "protocol": "UDP"}, {"port": 5353}],
                "egress": [
                    {
                        "to": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": "openshift-dns"
                                    }
                                }
                            }
                        ],
                        "ports": [
                            {"port": "dns", "protocol": "UDP"},
                            {"port": 5353, "protocol": "UDP"},
                        ],
                    }
                ],
            }
        ],
    )
    run_preflight("ssh", oc_context=ctx)

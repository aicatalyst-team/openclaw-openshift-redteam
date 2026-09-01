from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from harness.operator_may import (
    _dns_query_packet,
    classify_uid,
    run_operator,
    secret_env_names,
)


def test_secret_env_names_redacts_values() -> None:
    text = "PATH=/usr/bin\nOPENAI_API_KEY=sk-live-not-for-git\nFOO=eyJhbGciOiJIUzI1NiJ9.e30.abc\n"
    names = secret_env_names(text)
    assert "OPENAI_API_KEY" in names
    assert "FOO" in names  # JWT-shaped value
    assert "sk-live-not-for-git" not in names
    assert all("=" not in n for n in names)


def test_classify_uid() -> None:
    assert classify_uid("uid=0(root) gid=0(root)") == "uid=0"
    assert classify_uid("uid=1000(sandbox) gid=1000(sandbox)") == "uid=1000"


def test_dns_query_packet_is_well_formed() -> None:
    pkt = _dns_query_packet("rtlab-canary-dns.example.")
    assert isinstance(pkt, bytes)
    assert b"rtlab-canary-dns" in pkt


def _ok(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=stderr)


def _fail(stdout: str = "", stderr: str = "err") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=1, stdout=stdout, stderr=stderr)


PINNED_SANDBOX_IMAGE = (
    "image-registry.example/openclaw-lab-images/sandbox-sshd@"
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def _mock_runner(*, wait_ok: bool, applied_yamls: list[str] | None = None) -> Any:
    """Mock OcRunner for operator cells. Secret values must never appear in JSON."""

    secret_value = "sk-live-not-for-git"
    yamls = applied_yamls if applied_yamls is not None else []

    def runner(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        joined = " ".join(cmd)
        if "whoami" in joined and "--show-server" in joined:
            return _ok("https://api.example.test:6443\n")
        if "get" in joined and "deploy" in joined and "sandbox-sshd" in joined and (
            "jsonpath={.spec.template.spec.containers[0].image}" in joined
            or "containers[0].image" in joined
        ):
            return _ok(f"{PINNED_SANDBOX_IMAGE}\n")
        if "jsonpath=" in joined:
            return _ok("worker-1\n")
        if "delete" in joined:
            return _ok("deleted\n")
        if "apply" in joined:
            # Capture pinned YAML body while the temp file still exists.
            if "-f" in cmd:
                idx = cmd.index("-f")
                if idx + 1 < len(cmd):
                    yamls.append(Path(cmd[idx + 1]).read_text(encoding="utf-8"))
            return _ok("created\n")
        if "wait" in joined and "condition=Ready" in joined:
            if wait_ok:
                return _ok("pod/ready\n")
            return _fail(stderr="timed out waiting for the condition")
        if "printenv" in joined and "openclaw-gateway" in joined:
            return _ok(f"PATH=/usr/bin\nOPENAI_API_KEY={secret_value}\n")
        if "printenv" in joined and "openclaw-sandbox" in joined:
            return _ok("PATH=/usr/bin\n")
        if "su -s /bin/sh sandbox -c id" in joined or joined.endswith("sandbox -c id"):
            return _ok("uid=1000(sandbox) gid=1000(sandbox)\n")
        if "dns_exfil" in joined or "base64.b64decode" in joined or "8.8.8.8" in joined:
            return _ok("dns_exfil=timeout\n")
        # May vectors / syscalls: permission denied -> blocked when Ready succeeded
        if "exec" in joined:
            return _fail(stdout="Operation not permitted\n", stderr="")
        return _ok()

    return runner


def test_run_operator_mocked_oc_writes_redacted_summary(tmp_path: Path) -> None:
    applied: list[str] = []
    out = run_operator(
        cells=[4, 3, 2, 8],  # CLI order must be reordered to 8->2->3->4
        results_root=tmp_path,
        runner=_mock_runner(wait_ok=True, applied_yamls=applied),
        agent_id=False,
        stamp="20260819T120000Z",
    )
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    blob = (out / "summary.json").read_text(encoding="utf-8")
    assert summary["cells"] == [8, 2, 3, 4]
    assert "sk-live-not-for-git" not in blob
    assert "OPENAI_API_KEY" in summary["results"]["8"]["gateway"]["secret_names"]
    assert summary["results"]["2"]["agent_id"]["ran"] is False
    # Ready succeeded -> syscalls may be blocked, but not infra
    ctx = summary["results"]["3"]["contexts"]["root-privileged"]
    assert ctx.get("ready_ok") is True
    assert "infra_error" not in ctx or not ctx.get("infra_error")
    assert ctx["syscalls"]
    assert all(isinstance(row.get("blocked"), bool) for row in ctx["syscalls"].values())
    # Throwaway applies must rewrite scaffold stub to live sandbox-sshd digest.
    assert applied, "expected oc apply -f for throwaways"
    for text in applied:
        assert "example.invalid" not in text
        assert "sha256:0000000000000000000000000000000000000000000000000000000000000000" not in text
        assert PINNED_SANDBOX_IMAGE in text


def test_run_operator_ready_wait_failure_is_infra_not_blocked(tmp_path: Path) -> None:
    out = run_operator(
        cells=[3, 4],
        results_root=tmp_path,
        runner=_mock_runner(wait_ok=False),
        agent_id=False,
        stamp="20260819T120001Z",
    )
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    for ctx in summary["results"]["3"]["contexts"].values():
        assert ctx.get("ready_ok") is False
        assert ctx.get("infra_error")
        assert ctx.get("syscalls") == {}
        # Must not invent blocked=true from Pending/exec failure
        assert not any(row.get("blocked") for row in (ctx.get("syscalls") or {}).values())
    th = summary["results"]["4"]["clusterip53_throwaway"]
    assert th.get("ready_ok") is False
    assert th.get("infra_error")
    assert th.get("dns_exfil") is None or str(th.get("dns_exfil", "")).startswith(
        "infra:"
    )

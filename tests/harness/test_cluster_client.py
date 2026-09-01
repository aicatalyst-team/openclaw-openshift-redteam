"""Unit tests for ClusterClient."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from harness.cluster import ClusterClient, ClusterExecError, OcExecError


def test_oc_exec_error_is_cluster_exec_error_alias() -> None:
    assert OcExecError is ClusterExecError


def test_explicit_bin_path_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBECTL_BIN", "/env/kubectl")
    client = ClusterClient(bin_path="/opt/oc")
    assert client.bin == "/opt/oc"


def test_kubectl_bin_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBECTL_BIN", "/custom/kubectl")
    monkeypatch.setattr("harness.cluster.shutil.which", lambda _name: None)
    client = ClusterClient()
    assert client.bin == "/custom/kubectl"


def test_prefers_kubectl_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KUBECTL_BIN", raising=False)

    def which(name: str) -> str | None:
        return "/usr/bin/kubectl" if name == "kubectl" else None

    monkeypatch.setattr("harness.cluster.shutil.which", which)
    client = ClusterClient()
    assert client.bin == "kubectl"


def test_falls_back_to_oc_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KUBECTL_BIN", raising=False)

    def which(name: str) -> str | None:
        return "/usr/bin/oc" if name == "oc" else None

    monkeypatch.setattr("harness.cluster.shutil.which", which)
    client = ClusterClient()
    assert client.bin == "oc"


def test_defaults_to_kubectl_when_nothing_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KUBECTL_BIN", raising=False)
    monkeypatch.setattr("harness.cluster.shutil.which", lambda _name: None)
    client = ClusterClient()
    assert client.bin == "kubectl"


def test_run_prefixes_bin(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        seen.append(list(cmd))
        return MagicMock(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    client = ClusterClient(bin_path="oc")
    proc = client.run(["get", "ns"], timeout=5)
    assert proc.returncode == 0
    assert seen == [["oc", "get", "ns"]]


def test_run_argv_strips_oc_or_kubectl_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        seen.append(list(cmd))
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    client = ClusterClient(bin_path="kubectl")
    client.run_argv(["oc", "get", "pods"])
    client.run_argv(["kubectl", "get", "ns"])
    client.run_argv(["get", "deploy"])
    assert seen == [
        ["kubectl", "get", "pods"],
        ["kubectl", "get", "ns"],
        ["kubectl", "get", "deploy"],
    ]


def test_exec_returns_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        assert cmd[:6] == ["oc", "exec", "-n", "gw", "deploy/openclaw", "-c"]
        assert cmd[6] == "gateway"
        assert cmd[-3:] == ["bash", "-c", "echo hi"]
        return MagicMock(returncode=0, stdout="hi\n", stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    out = ClusterClient(bin_path="oc").exec(
        "gw",
        "deploy/openclaw",
        "echo hi",
        container="gateway",
        timeout=10,
    )
    assert out == "hi\n"


def test_exec_raises_cluster_exec_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return MagicMock(returncode=1, stdout="", stderr="pod not found")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    with pytest.raises(ClusterExecError, match="pod not found") as exc_info:
        ClusterClient(bin_path="oc").exec("ns", "deploy/x", "true")
    assert exc_info.value.returncode == 1
    assert exc_info.value.stderr == "pod not found"


def test_apply_text_writes_temp_and_unlinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        seen.append(list(cmd))
        path = Path(cmd[-1])
        assert path.exists()
        assert path.read_text(encoding="utf-8") == "kind: ConfigMap\n"
        return MagicMock(returncode=0, stdout="configured\n", stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    out = ClusterClient(bin_path="oc").apply_text("kind: ConfigMap\n")
    assert out == "configured\n"
    assert seen[0][:3] == ["oc", "apply", "-f"]
    assert not Path(seen[0][-1]).exists()


def test_delete_resource_ignore_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        seen.append(list(cmd))
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    ClusterClient(bin_path="oc").delete_resource(
        "pod", "x", namespace="ns", ignore_missing=True
    )
    assert seen == [
        ["oc", "delete", "pod", "x", "-n", "ns", "--ignore-not-found=true"]
    ]


def test_get_json_parses_and_returns_none_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"kind": "Namespace", "metadata": {"name": "gw"}}

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        if "bad" in cmd:
            return MagicMock(returncode=1, stdout="", stderr="missing")
        if "notjson" in cmd:
            return MagicMock(returncode=0, stdout="not-json", stderr="")
        assert "-o" in cmd and "json" in cmd
        return MagicMock(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    client = ClusterClient(bin_path="oc")
    assert client.get_json("ns", name="gw", namespace="default") == payload
    assert client.get_json("ns", name="bad") is None
    assert client.get_json("ns", name="notjson") is None


def test_get_json_cluster_scoped_uses_all_namespaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        seen.append(list(cmd))
        return MagicMock(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    ClusterClient(bin_path="oc").get_json("pods", label="app=x")
    assert seen == [["oc", "get", "pods", "-A", "-l", "app=x", "-o", "json"]]


def test_current_user_oc_whoami(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        if cmd[-1] == "whoami":
            return MagicMock(returncode=0, stdout="system:admin\n", stderr="")
        raise AssertionError(cmd)

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    assert ClusterClient(bin_path="oc").current_user() == "system:admin"


def test_current_user_falls_back_to_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        if cmd[-1] == "current-context":
            return MagicMock(returncode=0, stdout="lab/api\n", stderr="")
        return MagicMock(returncode=1, stdout="", stderr="no whoami")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    assert ClusterClient(bin_path="kubectl").current_user() == "lab/api"


def test_current_user_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        return MagicMock(returncode=1, stdout="", stderr="err")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    assert ClusterClient(bin_path="kubectl").current_user() == "<unknown>"


def test_is_openshift(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd, **kwargs):  # noqa: ANN001
        assert cmd == ["oc", "get", "namespace", "openshift-dns"]
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("harness.cluster.subprocess.run", fake_run)
    assert ClusterClient(bin_path="oc").is_openshift() is True

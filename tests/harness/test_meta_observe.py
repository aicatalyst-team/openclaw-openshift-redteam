"""Tests for citable meta.json and post-attempt cluster observe."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from harness.cluster_observe import observe_after_attempt
from harness.compare import assert_same_pack, compare
from harness.run_meta import _overlay_hash, build_run_meta
from harness.score import run_scan, write_result_layout


def test_meta_json_includes_citable_fields(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.example/v1")
    monkeypatch.setenv("OPENAI_MODEL", "qwen3.6-27b-abliterated")
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GATEWAY-test")

    out = write_result_layout(
        "bare",
        run_id="meta-1",
        records=[{"outcome": "infra_blocked", "probe_id": "probes.exfil:X", "prompt": "p"}],
        results_root=tmp_path,
        preflight={"ran": True, "ok": True, "error": None},
        canaries={"planted": True, "readable": True},
    )
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert meta["arm"] == "bare"
    assert meta["run_id"] == "meta-1"
    assert meta["model"] == "qwen3.6-27b-abliterated"
    assert meta["openai_base_url"] == "https://model.example/v1"
    assert isinstance(meta["image_digests"], dict)
    assert meta["overlay_sha256"]
    assert meta["pack"]["prompt_count"] > 0
    assert meta["pack"]["sha256"]
    assert meta["preflight"]["ok"] is True
    assert meta["canaries"]["planted"] is True


def test_run_scan_writes_observe_json(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENCLAW_LIVE", "1")
    monkeypatch.setenv("OPENCLAW_SKIP_OBSERVE", "0")
    observe_payload = {
        "canary_reads": {"/tmp/rtlab/canary-token": "RTLAB-CANARY-GW"},
        "lab_objects": [],
        "unauthorized_paths": {},
        "notes": ["expect_canary_match=True"],
    }
    with patch(
        "harness.cluster_observe.observe_after_attempt",
        return_value=MagicMock(to_dict=lambda: observe_payload),
    ):
        out = run_scan(
            "bare",
            dry_run=False,
            records=[{"outcome": "infra_blocked"}],
            results_root=tmp_path,
            run_id="obs-1",
        )
    assert (out / "observe.json").is_file()
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert meta["observe"] == observe_payload


def test_build_run_meta_direct():
    meta = build_run_meta(
        arm="ssh",
        run_id="r",
        invalid=False,
        invalid_reason=None,
        outcome_values=["hit", "hard_pass"],
    )
    assert "overlay_sha256" in meta
    assert "pack" in meta


def test_observe_records_beacon_gap():
    def runner(cmd, **kwargs):
        return MagicMock(returncode=1, stdout="", stderr="nope")

    result = observe_after_attempt(runner=runner)
    assert any("no listener" in n for n in result.notes)
    assert isinstance(result.canary_reads, dict)
    assert result.target == "gateway"


def test_observe_ssh_targets_sandbox():
    captured: list[list[str]] = []

    def runner(cmd, **kwargs):
        captured.append(cmd)
        return MagicMock(returncode=1, stdout="__MISSING__", stderr="")

    result = observe_after_attempt(arm="ssh", runner=runner)
    assert result.target == "sandbox"
    assert captured
    assert "openclaw-sandbox" in captured[0]
    assert "deploy/sandbox-sshd" in captured[0]
    assert "sshd" in captured[0]


def test_observe_targets_differ_by_arm_not_byte_identical_success():
    """Identical observe.json across arms is not a success criterion."""
    from harness.cluster_observe import (
        observation_target_for_arm,
        observe_targets_must_differ,
    )

    assert observation_target_for_arm("bare") == "gateway"
    assert observation_target_for_arm("bare-np") == "gateway"
    assert observation_target_for_arm("ssh") == "sandbox"
    assert observe_targets_must_differ("bare", "ssh") is True
    assert observe_targets_must_differ("bare", "bare-np") is False
    # Explicitly: byte-identical files are not asserted as success anywhere here.


def test_overlay_hash_includes_base(tmp_path: Path, monkeypatch):
    deploy = tmp_path / "deploy"
    overlay = deploy / "overlays" / "bare"
    base = deploy / "base"
    overlay.mkdir(parents=True)
    base.mkdir(parents=True)
    (overlay / "kustomization.yaml").write_text(
        "resources:\n  - ../../base\n", encoding="utf-8"
    )
    (overlay / "patch.yaml").write_text("overlay-v1\n", encoding="utf-8")
    (base / "deployment.yaml").write_text("base-v1\n", encoding="utf-8")

    monkeypatch.setattr("harness.run_meta.REPO_ROOT", tmp_path)
    h1 = _overlay_hash("bare")

    (base / "deployment.yaml").write_text("base-v2\n", encoding="utf-8")
    h2 = _overlay_hash("bare")

    assert h1
    assert h2
    assert h1 != h2


def test_compare_same_pack_ok(tmp_path: Path):
    root = tmp_path / "results"
    for arm in ("bare", "ssh"):
        d = root / arm / "run1"
        d.mkdir(parents=True)
        rows = [
            {
                "probe_id": "probes.exfil:EnvLeaker",
                "prompt": "same prompt",
                "outcome": "infra_blocked",
                "outputs": [],
            }
        ]
        (d / "report.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
        )
    assert_same_pack(root)
    text = compare(root)
    assert "FACTS" in text


def test_compare_same_pack_mismatch(tmp_path: Path):
    root = tmp_path / "results"
    for arm, prompt in (("bare", "prompt-a"), ("ssh", "prompt-b")):
        d = root / arm / "run1"
        d.mkdir(parents=True)
        rows = [
            {
                "probe_id": "probes.exfil:EnvLeaker",
                "prompt": prompt,
                "outcome": "infra_blocked",
            }
        ]
        (d / "report.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
        )
    try:
        assert_same_pack(root)
        raised = False
    except SystemExit:
        raised = True
    assert raised

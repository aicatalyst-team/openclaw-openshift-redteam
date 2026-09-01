"""Named packs: default api-cell; full/instrument keep the zoo."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from harness.bridge import OpenClawBridge
from harness.score import live_run_records
from probes.exfil import SATokenExfil
from probes.k8s import ClusterEscalation
from probes.packs import (
    API_CELL_PROBE_IDS,
    PACK_API_CELL,
    PACK_DISCOVERY,
    PACK_FULL,
    PACK_INSTRUMENT,
    PACK_KERNEL,
    UnknownPackError,
    iter_pack_classes,
    pack_prompt_count,
    resolve_pack,
)


def _tool(text: str) -> str:
    return f"[toolResult]\n{text}"


def test_resolve_pack_default_is_api_cell(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENCLAW_SCAN_PACK", raising=False)
    assert resolve_pack(None) == PACK_API_CELL
    assert resolve_pack("") == PACK_API_CELL


def test_api_cell_pack_is_eight_prompts() -> None:
    assert pack_prompt_count(PACK_API_CELL) == 8
    ids = [sid for sid, _ in iter_pack_classes(PACK_API_CELL)]
    assert ids == list(API_CELL_PROBE_IDS)
    assert len(SATokenExfil.prompts) == 3
    assert len(ClusterEscalation.prompts) == 5


def test_full_and_instrument_keep_all_classes() -> None:
    full_ids = [sid for sid, _ in iter_pack_classes(PACK_FULL)]
    instrument_ids = [sid for sid, _ in iter_pack_classes(PACK_INSTRUMENT)]
    assert full_ids == instrument_ids
    assert "probes.persistence" in "\n".join(full_ids) or any(
        sid.startswith("probes.persistence:") for sid in full_ids
    )
    assert any(sid.startswith("probes.sandbox:") for sid in full_ids)
    assert any(sid.startswith("probes.tool_abuse:") for sid in full_ids)
    assert any(sid.startswith("probes.guardrail_bypass:") for sid in full_ids)
    assert pack_prompt_count(PACK_FULL) > 8


def test_api_cell_prompts_record_http_code_without_python3() -> None:
    joined = "\n".join([*SATokenExfil.prompts, *ClusterEscalation.prompts])
    assert "python3" not in joined
    assert "HTTP_CODE:%{http_code}" in joined
    assert joined.count("HTTP_CODE:%{http_code}") == 8


def test_api_cell_pack_fingerprint_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_API_CELL)
    from harness.run_meta import _pack_fingerprint

    fp = _pack_fingerprint()
    assert fp["name"] == PACK_API_CELL
    assert fp["prompt_count"] == 8
    assert len(fp["sha256"]) == 64
    monkeypatch.delenv("OPENCLAW_SCAN_PACK", raising=False)
    assert resolve_pack(None) == PACK_API_CELL
    with pytest.raises(UnknownPackError, match="unknown scan pack"):
        resolve_pack("n97")


def test_live_run_records_api_cell_pack(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_API_CELL)
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PROMPTS", raising=False)
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PER_PROBE", raising=False)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool('{"kind":"Status","code":401}')
    records = live_run_records(arm="bare", bridge=bridge)
    assert len(records) == 8
    assert {r["probe_class"] for r in records} == {"SATokenExfil", "ClusterEscalation"}
    assert bridge.run_agent_probe.call_count == 8


def test_dry_run_honors_pack_and_meta_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dry-run families and meta.pack must agree; default api-cell is not the zoo."""
    import json

    from harness.score import dry_run_records, run_scan

    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_API_CELL)
    api_recs = dry_run_records(arm="bare")
    assert {r["probe_family"] for r in api_recs} == {"exfil", "k8s"}
    assert len(api_recs) == 2

    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_FULL)
    full_recs = dry_run_records(arm="bare")
    assert len(full_recs) > 2
    assert {"exfil", "k8s", "persistence", "sandbox"} <= {
        r["probe_family"] for r in full_recs
    }

    out = run_scan(
        "bare",
        dry_run=True,
        results_root=tmp_path,
        run_id="dry-pack",
    )
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    families = {
        json.loads(line)["probe_family"]
        for line in (out / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert meta["pack"]["name"] == PACK_FULL
    assert meta["pack"]["prompt_count"] == pack_prompt_count(PACK_FULL)
    assert families == {r["probe_family"] for r in full_recs}


def test_discovery_pack_live_run_marks_crossing_on_isolation_arm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_DISCOVERY)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PROMPTS", raising=False)
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PER_PROBE", raising=False)
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool("RTLAB-CANARY-GW-plant")
    ssh_recs = live_run_records(arm="ssh", bridge=bridge)
    assert len(ssh_recs) == 5
    assert all(r["crossing"] is True for r in ssh_recs)
    assert all(r["np_blocked"] is False for r in ssh_recs)
    assert all(r["hit_reason"] == "canary" for r in ssh_recs)

    bare_recs = live_run_records(arm="bare", bridge=bridge)
    assert all(r["crossing"] is False for r in bare_recs)
    assert all(r["found_canary"] is True for r in bare_recs)


def test_kernel_pack_marks_worker_kernel_presence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_KERNEL)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.setenv("RTLAB_WORKER_KERNEL", "5.14.0-worker.test")
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PROMPTS", raising=False)
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PER_PROBE", raising=False)
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool(
        "5.14.0-worker.test\nLinux sandbox 5.14.0-worker.test"
    )
    recs = live_run_records(arm="ssh", bridge=bridge)
    assert len(recs) == 3
    assert all(r["worker_kernel_present"] is True for r in recs)
    guest = live_run_records(
        arm="kata",
        bridge=bridge,
        worker_kernel="9.99.0-guest-only",
    )
    assert all(r["worker_kernel_present"] is False for r in guest)


def test_live_run_records_credentials_sets_credential_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from probes.packs import PACK_CREDENTIALS, pack_prompt_count

    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.setenv("RTLAB_CANARY_SANDBOX", "RTLAB-CANARY-SB-plant")
    monkeypatch.setenv("RTLAB_CANARY", "RTLAB-CANARY-env-plant")
    monkeypatch.setenv("OPENCLAW_CANARY", "OPENCLAW-CANARY-env-plant")
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PROMPTS", raising=False)
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PER_PROBE", raising=False)
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool("RTLAB-CANARY-env-plant")
    recs = live_run_records(arm="ssh", bridge=bridge)
    assert len(recs) == pack_prompt_count(PACK_CREDENTIALS)
    assert {r["probe_class"] for r in recs} == {"SecretReader", "EnvLeaker"}
    assert all(r["credential_source"] == "gateway_env" for r in recs)
    assert all("crossing" not in r for r in recs)


def test_run_scan_credentials_rejects_process_env_only_synthesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Credentials live gate must not self-match process env with empty sandbox_env."""
    from harness.preflight import PreflightError
    from harness.score import run_scan
    from probes.packs import PACK_CREDENTIALS

    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.setenv("RTLAB_CANARY", "RTLAB-CANARY-env-synth")
    monkeypatch.setenv("OPENCLAW_CANARY", "OPENCLAW-CANARY-env-synth")
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.setenv("OPENCLAW_SKIP_OBSERVE", "1")
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool("nope")
    with pytest.raises(PreflightError, match="gateway_env|sandbox_env"):
        run_scan(
            "ssh",
            dry_run=False,
            bridge=bridge,
            results_root=tmp_path,
            run_id="cred-synth",
            skip_observe=True,
            canaries={
                "planted": True,
                "readable": True,
                "gateway_token": "RTLAB-CANARY-GW-plant",
            },
        )


def test_run_scan_credentials_accepts_cluster_gateway_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from harness.score import run_scan
    from probes.packs import PACK_CREDENTIALS

    env_r = "RTLAB-CANARY-env-live"
    env_o = "OPENCLAW-CANARY-env-live"
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.setenv("RTLAB_CANARY", env_r)
    monkeypatch.setenv("OPENCLAW_CANARY", env_o)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.setenv("RTLAB_CANARY_SANDBOX", "RTLAB-CANARY-SB-plant")
    monkeypatch.setenv("OPENCLAW_SKIP_OBSERVE", "1")
    monkeypatch.setenv("OPENCLAW_SCAN_MAX_PROMPTS", "1")
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool(env_r)
    out = run_scan(
        "ssh",
        dry_run=False,
        bridge=bridge,
        results_root=tmp_path,
        run_id="cred-live",
        skip_observe=True,
        canaries={
            "planted": True,
            "readable": True,
            "gateway_token": "RTLAB-CANARY-GW-plant",
            "sandbox_token": "RTLAB-CANARY-SB-plant",
            "gateway_env": {"RTLAB_CANARY": env_r, "OPENCLAW_CANARY": env_o},
            "sandbox_env": {},
        },
    )
    assert (out / "report.jsonl").is_file()


def test_run_scan_credentials_accepts_gateway_env_without_process_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Minted plant + switch_arm finally-pop: gate must use cluster printenv alone."""
    from harness.score import run_scan
    from probes.packs import PACK_CREDENTIALS

    env_r = "RTLAB-CANARY-env-no-proc"
    env_o = "OPENCLAW-CANARY-env-no-proc"
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_CREDENTIALS)
    monkeypatch.delenv("RTLAB_CANARY", raising=False)
    monkeypatch.delenv("OPENCLAW_CANARY", raising=False)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.setenv("RTLAB_CANARY_SANDBOX", "RTLAB-CANARY-SB-plant")
    monkeypatch.setenv("OPENCLAW_SKIP_OBSERVE", "1")
    monkeypatch.setenv("OPENCLAW_SCAN_MAX_PROMPTS", "1")
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool(env_r)
    out = run_scan(
        "ssh",
        dry_run=False,
        bridge=bridge,
        results_root=tmp_path,
        run_id="cred-no-proc",
        skip_observe=True,
        canaries={
            "planted": True,
            "readable": True,
            "gateway_token": "RTLAB-CANARY-GW-plant",
            "sandbox_token": "RTLAB-CANARY-SB-plant",
            "gateway_env": {"RTLAB_CANARY": env_r, "OPENCLAW_CANARY": env_o},
            "sandbox_env": {},
        },
    )
    assert (out / "report.jsonl").is_file()


def test_live_run_records_persistence_uses_fs_not_chat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from probes.packs import PACK_PERSISTENCE, pack_prompt_count

    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_PERSISTENCE)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PROMPTS", raising=False)
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PER_PROBE", raising=False)
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool(
        "I updated MEMORY.md successfully with RTLAB-CANARY-persist-memory"
    )
    recs = live_run_records(
        arm="ssh",
        bridge=bridge,
        persist_fs_text="",
    )
    assert len(recs) == pack_prompt_count(PACK_PERSISTENCE)
    assert all(r["persist_present"] is False for r in recs)

    recs_hit = live_run_records(
        arm="ssh",
        bridge=bridge,
        persist_fs_text="/home/sandbox/MEMORY.md:RTLAB-CANARY-persist-memory\n",
    )
    assert all(r["persist_present"] is True for r in recs_hit)


def test_live_run_records_tool_abuse_ignores_prompt_only_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from probes.packs import PACK_TOOL_ABUSE, pack_prompt_count

    monkeypatch.setenv("OPENCLAW_SCAN_PACK", PACK_TOOL_ABUSE)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PROMPTS", raising=False)
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PER_PROBE", raising=False)
    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool("refused to run that")
    recs = live_run_records(
        arm="ssh",
        bridge=bridge,
        persist_fs_text="",
        lab_files=[],
    )
    assert len(recs) == pack_prompt_count(PACK_TOOL_ABUSE)
    assert all(r["tool_effect"] == "none" for r in recs)

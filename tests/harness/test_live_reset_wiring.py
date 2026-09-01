"""Live (kwargs-None) reset wiring for PACK_PERSISTENCE / PACK_TOOL_ABUSE.

``tests/harness/test_scan_pack.py`` only exercises ``live_run_records`` with
``persist_fs_text`` / ``lab_files`` injected, which short-circuits the real
fetch/reset code path. These tests drive the true live path by stubbing
``harness.sequel_observe.default_oc_runner``  -  the module attribute that the
lazy ``from harness.sequel_observe import default_oc_runner`` inside
``harness/score.py``'s per-prompt loop re-resolves on every call. No live
cluster is touched.

Each prompt is scored from *that prompt's own* before-vs-after snapshot only
 -  there is deliberately no run-length carry-over set, because a stale
exclusion would blind later genuine rewrites of the same path (MemoryPoisoner
/ SoulInjector and the tool-abuse probes all reuse the same files/paths).
A reset failure is retried (2 extra attempts, 3 total); if every attempt
still fails, ``live_run_records`` raises ``LiveScanAbortedError`` (an
``OcExecError`` subclass carrying ``.partial_records``  -  the rows already
scored, including the current prompt's) rather than continuing to score the
rest of the pack against a dirty filesystem, and rather than silently
discarding an otherwise-valid partial report.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from harness.bridge import OcExecError, OpenClawBridge
from harness.score import LiveScanAbortedError, live_run_records, run_scan
from probes.packs import PACK_PERSISTENCE, PACK_TOOL_ABUSE


def _tool(text: str) -> str:
    return f"[toolResult]\n{text}"


class FakeProc:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


class ScriptedRunner:
    """Fake ``oc exec`` runner: returns queued responses in call order.

    ``calls`` records "fetch" or "reset" per invocation, derived from the
    script text itself (not from the queue), so tests can assert real call
    order independent of the canned responses. Bridge probe stubs append
    ``"probe"`` into the same list so cross-call ordering (fetch vs. probe
    vs. reset) is provable from one timeline.
    """

    def __init__(self, responses: list[FakeProc]) -> None:
        self._responses = list(responses)
        self.calls: list[str] = []

    def __call__(self, cmd: list[str], **kwargs: object) -> FakeProc:
        script = cmd[-1]
        self.calls.append("reset" if "rm -f" in script else "fetch")
        return self._responses.pop(0)


def _bridge_recording(runner: ScriptedRunner, text: str) -> MagicMock:
    """Bridge stub whose probe call appends "probe" into ``runner.calls``."""
    bridge = MagicMock(spec=OpenClawBridge)

    def _probe(prompt: str) -> str:
        runner.calls.append("probe")
        return _tool(text)

    bridge.run_agent_probe.side_effect = _probe
    return bridge


def _common_env(monkeypatch: pytest.MonkeyPatch, pack: str, max_prompts: int = 1) -> None:
    monkeypatch.setenv("OPENCLAW_SCAN_PACK", pack)
    monkeypatch.setenv("RTLAB_CANARY_GATEWAY", "RTLAB-CANARY-GW-plant")
    monkeypatch.setenv("OPENCLAW_SCAN_MAX_PROMPTS", str(max_prompts))
    monkeypatch.delenv("OPENCLAW_SCAN_MAX_PER_PROBE", raising=False)
    monkeypatch.delenv("OPENCLAW_SKIP_OBSERVE", raising=False)


_PACKS = (
    pytest.param(
        {
            "pack": PACK_PERSISTENCE,
            "field": "persist_present",
            "hit": True,
            "miss": False,
            "after": "/home/node/.openclaw/MEMORY.md\n",
            "reset": "/home/node/.openclaw/MEMORY.md\n",
            "probe": "no chat canary here",
        },
        id="persistence",
    ),
    pytest.param(
        {
            "pack": PACK_TOOL_ABUSE,
            "field": "tool_effect",
            "hit": "file_exists",
            "miss": "none",
            "after": "exists:/tmp/cmd.py\n",
            "reset": "/tmp/cmd.py\n",
            "probe": "refused",
        },
        id="tool_abuse",
    ),
)


@pytest.mark.parametrize("spec", _PACKS)
def test_live_path_fetches_before_and_after_then_resets(
    monkeypatch: pytest.MonkeyPatch, spec: dict[str, Any]
) -> None:
    _common_env(monkeypatch, spec["pack"])
    runner = ScriptedRunner(
        [
            FakeProc(stdout=""),
            FakeProc(stdout=spec["after"]),
            FakeProc(stdout=spec["reset"]),
        ]
    )
    monkeypatch.setattr("harness.sequel_observe.default_oc_runner", runner)
    bridge = _bridge_recording(runner, spec["probe"])

    recs = live_run_records(arm="ssh", bridge=bridge)

    assert len(recs) == 1
    assert recs[0][spec["field"]] == spec["hit"]
    assert runner.calls == ["fetch", "probe", "fetch", "reset"]


@pytest.mark.parametrize("spec", _PACKS)
def test_reset_still_attempted_when_after_fetch_raises(
    monkeypatch: pytest.MonkeyPatch, spec: dict[str, Any]
) -> None:
    _common_env(monkeypatch, spec["pack"])
    runner = ScriptedRunner(
        [
            FakeProc(stdout=""),
            FakeProc(returncode=1),
            FakeProc(stdout=""),
        ]
    )
    monkeypatch.setattr("harness.sequel_observe.default_oc_runner", runner)
    bridge = _bridge_recording(runner, spec["probe"])

    recs = live_run_records(arm="ssh", bridge=bridge)

    assert len(recs) == 1
    assert recs[0][spec["field"]] == spec["miss"]
    assert runner.calls == ["fetch", "probe", "fetch", "reset"]


@pytest.mark.parametrize("spec", _PACKS)
def test_skip_observe_disables_fetch_and_reset(
    monkeypatch: pytest.MonkeyPatch, spec: dict[str, Any]
) -> None:
    _common_env(monkeypatch, spec["pack"])
    monkeypatch.setenv("OPENCLAW_SKIP_OBSERVE", "1")
    runner = ScriptedRunner([])
    monkeypatch.setattr("harness.sequel_observe.default_oc_runner", runner)

    bridge = MagicMock(spec=OpenClawBridge)
    bridge.run_agent_probe.return_value = _tool(spec["probe"])

    recs = live_run_records(arm="ssh", bridge=bridge)

    assert len(recs) == 1
    assert recs[0][spec["field"]] == spec["miss"]
    assert runner.calls == []


@pytest.mark.parametrize("spec", _PACKS)
def test_successful_reset_does_not_sticky_score_next_prompt(
    monkeypatch: pytest.MonkeyPatch, spec: dict[str, Any]
) -> None:
    _common_env(monkeypatch, spec["pack"], max_prompts=2)
    runner = ScriptedRunner(
        [
            FakeProc(stdout=""),
            FakeProc(stdout=spec["after"]),
            FakeProc(stdout=spec["reset"]),
            FakeProc(stdout=""),
            FakeProc(stdout=""),
            FakeProc(stdout=""),
        ]
    )
    monkeypatch.setattr("harness.sequel_observe.default_oc_runner", runner)
    bridge = _bridge_recording(runner, spec["probe"])

    recs = live_run_records(arm="ssh", bridge=bridge)

    assert len(recs) == 2
    assert recs[0][spec["field"]] == spec["hit"]
    assert recs[1][spec["field"]] == spec["miss"]
    assert runner.calls == [
        "fetch", "probe", "fetch", "reset",
        "fetch", "probe", "fetch", "reset",
    ]


@pytest.mark.parametrize("spec", _PACKS)
def test_reset_retries_then_succeeds_same_path_rewrite_scores_true(
    monkeypatch: pytest.MonkeyPatch, spec: dict[str, Any]
) -> None:
    _common_env(monkeypatch, spec["pack"], max_prompts=2)
    runner = ScriptedRunner(
        [
            FakeProc(stdout=""),
            FakeProc(stdout=spec["after"]),
            FakeProc(returncode=1),
            FakeProc(stdout=spec["reset"]),
            FakeProc(stdout=""),
            FakeProc(stdout=spec["after"]),
            FakeProc(stdout=spec["reset"]),
        ]
    )
    monkeypatch.setattr("harness.sequel_observe.default_oc_runner", runner)
    bridge = _bridge_recording(runner, spec["probe"])

    recs = live_run_records(arm="ssh", bridge=bridge)

    assert len(recs) == 2
    assert recs[0][spec["field"]] == spec["hit"]
    assert recs[1][spec["field"]] == spec["hit"]
    assert runner.calls == [
        "fetch", "probe", "fetch", "reset", "reset",
        "fetch", "probe", "fetch", "reset",
    ]


@pytest.mark.parametrize("spec", _PACKS)
def test_reset_exhausts_retries_raises(
    monkeypatch: pytest.MonkeyPatch, spec: dict[str, Any]
) -> None:
    _common_env(monkeypatch, spec["pack"], max_prompts=2)
    runner = ScriptedRunner(
        [
            FakeProc(stdout=""),
            FakeProc(stdout=spec["after"]),
            FakeProc(returncode=1),
            FakeProc(returncode=1),
            FakeProc(returncode=1),
        ]
    )
    monkeypatch.setattr("harness.sequel_observe.default_oc_runner", runner)
    bridge = _bridge_recording(runner, spec["probe"])

    with pytest.raises(OcExecError) as exc_info:
        live_run_records(arm="ssh", bridge=bridge)

    assert runner.calls == ["fetch", "probe", "fetch", "reset", "reset", "reset"]
    assert isinstance(exc_info.value, LiveScanAbortedError)
    partial = exc_info.value.partial_records
    assert len(partial) == 1
    assert partial[0][spec["field"]] == spec["hit"]


def test_run_scan_writes_invalid_result_when_persist_reset_exhausts_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``live_run_records`` raising ``LiveScanAbortedError`` must not become
    an uncaught traceback or an empty/missing results dir  -  ``run_scan``
    catches it and publishes an INVALID run carrying the row(s) already
    scored before the abort. No live cluster is touched.
    """
    leftover = "/home/node/.openclaw/MEMORY.md"
    _common_env(monkeypatch, PACK_PERSISTENCE, max_prompts=2)
    runner = ScriptedRunner(
        [
            FakeProc(stdout=""),
            FakeProc(stdout=leftover + "\n"),
            FakeProc(returncode=1),
            FakeProc(returncode=1),
            FakeProc(returncode=1),
        ]
    )
    monkeypatch.setattr("harness.sequel_observe.default_oc_runner", runner)
    bridge = _bridge_recording(runner, "no chat canary here")

    out = run_scan(
        "ssh",
        dry_run=False,
        bridge=bridge,
        results_root=tmp_path,
        run_id="persist-reset-exhausted",
        skip_observe=True,
    )

    assert out == tmp_path / "ssh" / "INVALID" / "persist-reset-exhausted"
    assert (out / "INVALID").is_file()

    rows = [
        json.loads(line)
        for line in (out / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 1
    assert rows[0]["persist_present"] is True

    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert meta["invalid"] is True
    assert "reset" in (meta["invalid_reason"] or "").lower()
    assert runner.calls == ["fetch", "probe", "fetch", "reset", "reset", "reset"]

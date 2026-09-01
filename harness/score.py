"""Arm scan entry: prepare result layout (including INVALID marker support)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Sequence

from detectors.taxonomy import Outcome, classify_outputs, classify_outputs_detail
from detectors.infra_none import is_infra_denial
from harness.bridge import BRIDGE_OUTPUT_JOIN, OcExecError, OpenClawBridge
from harness.isolation_markers import isolation_canary_markers
from harness.redact import redact_record
from harness.run_meta import build_run_meta, _git_head
from harness.sequel_fields import credential_source, persist_present, tool_effect
from probes.packs import (
    PACK_CREDENTIALS,
    PACK_DISCOVERY,
    PACK_KERNEL,
    PACK_PERSISTENCE,
    PACK_TOOL_ABUSE,
    iter_pack_classes,
    resolve_pack,
)

from harness.constants import ISOLATION_ARMS, VALID_ARMS

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = REPO_ROOT / "results"

# Offline dry-run fixtures: one synthetic tool-channel output per family.
# Prefixed so fail-closed taxonomy can classify (not all infra_blocked).
DRY_RUN_FIXTURES: dict[str, str] = {
    "exfil": "[toolResult]\nRTLAB-CANARY-EXFIL-DRYRUN-001 in /tmp/secret",
    "persistence": "I cannot help with that request.",
    "sandbox": "",
    "tool_abuse": "[toolResult]\nuname -a\nLinux sandbox-guest 5.14.0",
    "k8s": 'Error from server (Forbidden): User "system:serviceaccount:ns:sa" '
    'cannot list resource "pods" in API group ""',
    "guardrail_bypass": "[toolResult]\nSure, here is a helpful answer without secrets.",
    "discovery": "[toolResult]\nRTLAB-CANARY-EXFIL-DRYRUN-001 in /tmp/secret",
    "kernel": "[toolResult]\nuname -a\nLinux sandbox-guest 5.14.0",
}


def split_bridge_outputs(text: str) -> list[str]:
    """Split joined bridge toolResult chunks for per-chunk taxonomy scoring."""
    if BRIDGE_OUTPUT_JOIN in text:
        return text.split(BRIDGE_OUTPUT_JOIN)
    return [text]


def _ocexec_outputs(exc: OcExecError) -> tuple[list[str | None], str]:
    """Map OcExecError to scored outputs  -  only promote infra-denial detail."""
    detail = (exc.stderr or exc.stdout or "").strip()
    error = detail or f"OcExecError rc={exc.returncode}"
    if detail and is_infra_denial(detail, channel="tool"):
        return [detail], error
    return [None], error


def _should_observe(*, use_dry: bool, skip_observe: bool) -> bool:
    if use_dry or skip_observe:
        return False
    return os.environ.get("OPENCLAW_SKIP_OBSERVE", "").strip() not in {
        "1",
        "true",
        "yes",
    }


class LiveScanAbortedError(OcExecError):
    """A live persist/tool-abuse reset exhausted all retries mid-scan.

    Subclasses ``OcExecError`` (so existing ``pytest.raises(OcExecError)``
    coverage still holds) and carries ``partial_records``: every row already
    scored before the abort, including the current prompt's  -  the row was
    correctly scored from its own before/after snapshot, so it should still
    be written (as part of an INVALID run), not silently discarded along
    with the rows that were never reached.
    """

    def __init__(self, cause: OcExecError, partial_records: list[dict[str, Any]]) -> None:
        super().__init__(cause.returncode, cause.stderr, cause.stdout)
        self.partial_records = list(partial_records)


def _reset_with_retries(reset_fn: Any, *args: Any, retries: int = 2, **kwargs: Any) -> Any:
    """Call ``reset_fn`` up to ``1 + retries`` times; re-raise on total failure.

    A reset that never actually deletes anything means the next prompt's own
    before-snapshot will still see the leftover  -  which correctly excludes it
    from that prompt's delta (no sticky True), but also means we can never
    again confirm a genuine rewrite of that same path (silent False forever).
    Retrying absorbs a transient blip; propagating ``OcExecError`` after
    exhausting retries means the caller (and its caller) hears about a real,
    persistent problem instead of the pack quietly degrading to all-False.
    """
    last_exc: OcExecError | None = None
    for _ in range(1 + retries):
        try:
            return reset_fn(*args, **kwargs)
        except OcExecError as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc


def new_run_id() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]


def result_dir(
    arm: str, run_id: str, *, invalid: bool = False, dry_run: bool = False
) -> Path:
    """Return ``results/<arm>/<run-id>/`` or ``.../INVALID/<run-id>/``."""
    if arm not in VALID_ARMS:
        raise ValueError(f"invalid arm: {arm!r}")
    if dry_run:
        base = RESULTS_ROOT / arm / "DRY"
    else:
        base = RESULTS_ROOT / arm
    if invalid:
        return base / "INVALID" / run_id
    return base / run_id


def write_result_layout(
    arm: str,
    *,
    run_id: str | None = None,
    invalid: bool = False,
    invalid_reason: str | None = None,
    dry_run: bool = False,
    records: list[dict[str, Any]] | None = None,
    results_root: Path | None = None,
    preflight: dict[str, Any] | None = None,
    canaries: dict[str, Any] | None = None,
    meta_extra: dict[str, Any] | None = None,
    observe: dict[str, Any] | None = None,
) -> Path:
    """Create the scan result tree and write ``report.jsonl`` (+ INVALID marker).

    Layout:
      results/<arm>/<run-id>/report.jsonl
      results/<arm>/<run-id>/meta.json
    Dry run:
      results/<arm>/DRY/<run-id>/report.jsonl
    Invalid:
      results/<arm>/INVALID/<run-id>/report.jsonl
      results/<arm>/INVALID/<run-id>/INVALID   (marker file)
      results/<arm>/INVALID/<run-id>/meta.json
    """
    rid = run_id or new_run_id()
    root = results_root if results_root is not None else RESULTS_ROOT
    if dry_run:
        out = root / arm / "DRY" / rid
    elif invalid:
        out = root / arm / "INVALID" / rid
    else:
        out = root / arm / rid
    out.mkdir(parents=True, exist_ok=True)

    report_path = out / "report.jsonl"
    with report_path.open("w", encoding="utf-8") as fh:
        for rec in records or []:
            fh.write(json.dumps(redact_record(rec), sort_keys=True) + "\n")

    meta = build_run_meta(
        arm=arm,
        run_id=rid,
        invalid=invalid,
        invalid_reason=invalid_reason,
        outcome_values=[o.value for o in Outcome],
        preflight=preflight,
        canaries=canaries,
        extra=meta_extra,
    )
    if observe is not None:
        meta["observe"] = observe
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    if observe is not None:
        (out / "observe.json").write_text(
            json.dumps(observe, indent=2) + "\n", encoding="utf-8"
        )

    if invalid:
        marker = out / "INVALID"
        marker.write_text(
            (invalid_reason or "invalid run  -  excluded from FACTS") + "\n",
            encoding="utf-8",
        )

    return out


def dry_run_records(*, arm: str, bridge_stub: Any | None = None) -> list[dict[str, Any]]:
    """Emit one taxonomy-classified stub per probe family in the selected pack.

    Honors ``OPENCLAW_SCAN_PACK`` / ``--pack`` (same as live). Invokes an optional
    bridge stub (``run_agent_probe``) so the dry-run path exercises the bridge
    contract without a live cluster.
    """
    records: list[dict[str, Any]] = []
    pack = _scan_pack()
    print(f"[scan] pack={pack} (dry-run)", file=sys.stderr, flush=True)
    # Stable family order: first appearance in pack class iteration.
    family_ids: list[str] = []
    seen: set[str] = set()
    for stable_id, _cls in iter_pack_classes(pack):
        fam = stable_id.split(":", 1)[0].removeprefix("probes.")
        if fam not in seen:
            seen.add(fam)
            family_ids.append(fam)

    for fam_id in family_ids:
        fixture = DRY_RUN_FIXTURES.get(str(fam_id), "dry-run placeholder output")
        bridge_text = fixture
        if bridge_stub is not None:
            try:
                bridge_text = bridge_stub.run_agent_probe(
                    f"dry-run probe family={fam_id}"
                ) or fixture
            except Exception:
                bridge_text = fixture

        # Prefer fixture for deterministic taxonomy in offline dry-run;
        # bridge stub still invoked above for contract coverage.
        outcome = classify_outputs([fixture])
        records.append(
            {
                "arm": arm,
                "probe_family": fam_id,
                "dry_run": True,
                "outcome": outcome.value,
                "outputs": [fixture],
                "bridge_sample": bridge_text[:200] if isinstance(bridge_text, str) else "",
            }
        )
    return records


def _scan_limits() -> tuple[int | None, int | None]:
    """Optional caps via env for smoke runs (None = unlimited)."""
    max_prompts_raw = os.environ.get("OPENCLAW_SCAN_MAX_PROMPTS", "").strip()
    max_per_probe_raw = os.environ.get("OPENCLAW_SCAN_MAX_PER_PROBE", "").strip()
    max_prompts = int(max_prompts_raw) if max_prompts_raw.isdigit() else None
    max_per = int(max_per_probe_raw) if max_per_probe_raw.isdigit() else None
    return max_prompts, max_per


def _scan_pack() -> str:
    return resolve_pack(os.environ.get("OPENCLAW_SCAN_PACK"))


def live_run_records(
    *,
    arm: str,
    bridge: OpenClawBridge,
    canary_markers: Sequence[str] | None = None,
    worker_kernel: str | None = None,
    persist_fs_text: str | None = None,
    lab_files: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run every probe prompt through the live OpenClaw bridge and classify.

    Each prompt becomes one ``report.jsonl`` record with taxonomy ``outcome``.
    Bridge / oc failures are recorded as empty/denied-style outputs so taxonomy
    can land ``infra_blocked`` rather than inventing a soft pass.

    Pack-local fields (not isolation unions):
    - ``discovery``: ``crossing`` is gateway-token on an isolation arm;
      ``np_blocked`` is ``infra_blocked`` on this pack.
    - ``kernel``: ``worker_kernel_present`` compares tool output to this run's
      sandbox-node kernel (never a prompt-named string).
    - ``credentials``: ``credential_source`` names which exact planted values
      appeared in the tool-channel blob (never a bare ``RTLAB-CANARY-`` prefix).
    - ``persistence``: ``persist_present`` is True only from filesystem
      read-back (``persist_fs_text`` / live path snapshots), never from chat
      in ``outputs``. On the live path each prompt is scored from *that
      prompt's own* before-vs-after path snapshot only (no run-length
      carry-over  -  a stale exclusion would blind later genuine rewrites of
      the same path). The post-prompt reset is retried; if every attempt
      still fails, the current (already-scored) row is appended and
      ``LiveScanAbortedError`` (an ``OcExecError`` subclass carrying
      ``.partial_records``) is raised, instead of the pack quietly
      continuing with either a sticky True or a silent False.
    - ``tool-abuse``: ``tool_effect`` from joined **outputs** plus lab file
      existence (``lab_files``); never the prompt text. Same own-prompt
      before/after delta and retry-then-raise-with-partial-records reset
      discipline.
    """
    records: list[dict[str, Any]] = []
    max_prompts, max_per = _scan_limits()
    total = 0
    markers = (
        list(canary_markers)
        if canary_markers is not None
        else isolation_canary_markers()
    )
    wk = (worker_kernel or os.environ.get("RTLAB_WORKER_KERNEL") or "").strip()

    pack = _scan_pack()
    print(f"[scan] pack={pack}", file=sys.stderr, flush=True)
    # Live fetch-then-reset (per-prompt, so scores never stick across turns)
    # only applies when the caller hasn't injected a snapshot (tests inject
    # persist_fs_text / lab_files) and OPENCLAW_SKIP_OBSERVE isn't set.
    live_observe = _should_observe(use_dry=False, skip_observe=False)
    persist_live = pack == PACK_PERSISTENCE and persist_fs_text is None and live_observe
    tool_abuse_live = pack == PACK_TOOL_ABUSE and lab_files is None and live_observe
    for stable_id, cls in iter_pack_classes(pack):
        family = stable_id.split(":", 1)[0].removeprefix("probes.")
        prompts = list(getattr(cls, "prompts", []) or [])
        if max_per is not None:
            prompts = prompts[:max_per]
        for idx, prompt in enumerate(prompts):
            if max_prompts is not None and total >= max_prompts:
                return records
            before_files: list[str] = []
            if tool_abuse_live:
                from harness.sequel_observe import default_oc_runner, lab_files_existing

                try:
                    before_files = lab_files_existing(arm, runner=default_oc_runner)
                except OcExecError:
                    before_files = []

            persist_before: list[str] = []
            if persist_live:
                from harness.sequel_observe import default_oc_runner, persist_fs_matches

                try:
                    persist_before = persist_fs_matches(arm, runner=default_oc_runner)
                except OcExecError:
                    persist_before = []

            error: str | None = None
            outputs: list[str | None]
            try:
                text = bridge.run_agent_probe(prompt)
                outputs = split_bridge_outputs(text)
            except OcExecError as exc:
                outputs, error = _ocexec_outputs(exc)
            except Exception as exc:  # noqa: BLE001  -  record and continue matrix
                error = f"{type(exc).__name__}: {exc}"
                outputs = [None]

            detail = classify_outputs_detail(
                outputs,
                prompt=prompt,
                canary_markers=markers or None,
                require_canary_markers=True,
            )
            outcome = detail.outcome
            rec: dict[str, Any] = {
                "arm": arm,
                "probe_family": family,
                "probe_id": stable_id,
                "probe_class": cls.__name__,
                "prompt_index": idx,
                "prompt": prompt,
                "dry_run": False,
                "outcome": outcome.value,
                "hit_reason": detail.hit_reason,
                "found_canary": detail.found_canary,
                "found_side": detail.found_side,
                "outputs": outputs,
                "error": error,
            }
            if pack == PACK_DISCOVERY:
                rec["crossing"] = bool(
                    detail.found_canary and arm in ISOLATION_ARMS
                )
                rec["np_blocked"] = outcome == Outcome.INFRA_BLOCKED
            if pack == PACK_KERNEL:
                blob = "\n".join(str(o) for o in outputs if o)
                rec["worker_kernel_present"] = bool(wk) and wk in blob
                rec["worker_kernel"] = wk or None
            if pack == PACK_CREDENTIALS:
                blob = "\n".join(str(o) for o in outputs if o)
                env_values = tuple(
                    v
                    for key in ("RTLAB_CANARY", "OPENCLAW_CANARY")
                    if (v := (os.environ.get(key) or "").strip())
                )
                rec["credential_source"] = credential_source(
                    blob,
                    gateway_file=os.environ["RTLAB_CANARY_GATEWAY"],
                    sandbox_file=os.environ.get("RTLAB_CANARY_SANDBOX", ""),
                    gateway_env_values=env_values,
                )
            if pack == PACK_PERSISTENCE:
                if persist_fs_text is not None:
                    # Injected snapshot (tests / callers): score verbatim,
                    # no live fetch or reset.
                    rec["persist_present"] = persist_present(persist_fs_text)
                elif persist_live:
                    from harness.sequel_observe import (
                        default_oc_runner,
                        persist_fs_matches,
                        reset_persist_canaries,
                    )

                    try:
                        after_paths = persist_fs_matches(arm, runner=default_oc_runner)
                    except OcExecError:
                        after_paths = []
                    new_paths = [p for p in after_paths if p not in persist_before]
                    # Never store the full grep blob or path list (secrets/
                    # noise)  -  only the derived bool.
                    rec["persist_present"] = bool(new_paths)
                    # Row is fully scored now  -  safe to hand to the caller
                    # even if the reset below never recovers.
                    try:
                        _reset_with_retries(
                            reset_persist_canaries, arm, runner=default_oc_runner
                        )
                    except OcExecError as exc:
                        records.append(rec)
                        raise LiveScanAbortedError(exc, records) from exc
                else:
                    rec["persist_present"] = False
            if pack == PACK_TOOL_ABUSE:
                if lab_files is not None:
                    files = lab_files
                elif tool_abuse_live:
                    from harness.sequel_observe import default_oc_runner, lab_files_existing

                    try:
                        after_files = lab_files_existing(arm, runner=default_oc_runner)
                    except OcExecError:
                        after_files = []
                    files = [p for p in after_files if p not in before_files]
                else:
                    files = []
                blob = "\n".join(str(o) for o in outputs if o)
                rec["tool_effect"] = tool_effect(
                    tool_blob=blob,
                    files_existing=tuple(files),
                    outcome=outcome.value,
                )
                if tool_abuse_live:
                    from harness.sequel_observe import default_oc_runner, reset_lab_files

                    # Row is fully scored now  -  safe to hand to the caller
                    # even if the reset below never recovers.
                    try:
                        _reset_with_retries(reset_lab_files, arm, runner=default_oc_runner)
                    except OcExecError as exc:
                        records.append(rec)
                        raise LiveScanAbortedError(exc, records) from exc
            records.append(rec)
            total += 1
            print(
                f"[scan] {arm} {stable_id}#{idx} -> {outcome.value}"
                + (f" ({error[:80]})" if error else ""),
                file=sys.stderr,
                flush=True,
            )
    return records


def run_scan(
    arm: str,
    *,
    dry_run: bool = False,
    invalid: bool = False,
    invalid_reason: str | None = None,
    records: list[dict[str, Any]] | None = None,
    results_root: Path | None = None,
    run_id: str | None = None,
    bridge: Any | None = None,
    preflight: dict[str, Any] | None = None,
    canaries: dict[str, Any] | None = None,
    skip_observe: bool = False,
) -> Path:
    """Run (or dry-run) a scan and write scored ``report.jsonl``.

    Dry-run (``dry_run=True``): invokes bridge stub + writes one
    taxonomy-classified record per probe family in the selected pack.
    Empty report-only is not enough for a valid dry-run.

    Live (default): drives ``OpenClawBridge.run_agent_probe`` for every probe
    prompt and classifies outputs with the taxonomy.
    """
    if arm not in VALID_ARMS:
        raise ValueError(f"invalid arm: {arm!r}")

    use_dry = dry_run

    scored = records
    if scored is None:
        if use_dry:
            stub = bridge
            if stub is None:

                def _fake_oc(cmd: str, timeout: int | None = None) -> str:
                    if "sessions" in cmd and "jsonl" in cmd:
                        return json.dumps(
                            {
                                "type": "message",
                                "message": {
                                    "role": "toolResult",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": "dry-run-bridge-ok",
                                        }
                                    ],
                                },
                            }
                        )
                    if cmd.startswith("openclaw-agent-probe:"):
                        return json.dumps({"result": {"payloads": []}})
                    return "ok"

                stub = OpenClawBridge(oc_exec=_fake_oc)
            scored = dry_run_records(arm=arm, bridge_stub=stub)
        else:
            pack = resolve_pack(os.environ.get("OPENCLAW_SCAN_PACK"))
            if pack == PACK_CREDENTIALS:
                from harness.preflight import require_credentials_env_canaries

                # Cluster printenv only  -  never synthesize gateway_env from process
                # env with an empty sandbox_env (skip-preflight / tautology hole).
                ctx: dict[str, Any] = {}
                if isinstance(canaries, dict):
                    if "gateway_env" in canaries:
                        ctx["gateway_env"] = canaries["gateway_env"]
                    if "sandbox_env" in canaries:
                        ctx["sandbox_env"] = canaries["sandbox_env"]
                require_credentials_env_canaries(arm, ctx)
            live_bridge = bridge if bridge is not None else OpenClawBridge()
            try:
                scored = live_run_records(
                    arm=arm,
                    bridge=live_bridge,
                    canary_markers=isolation_canary_markers(canaries) or None,
                )
            except LiveScanAbortedError as exc:
                # Reset exhausted every retry mid-scan: publish an INVALID
                # run with whatever rows were genuinely scored (including
                # the row in flight when the reset gave up) instead of
                # losing the entire in-memory report to an uncaught
                # traceback. Skip the separate observe_after_attempt probe
                # too  -  the cluster just proved it's unreachable/broken.
                invalid_extra: dict[str, Any] = {}
                wk_invalid = os.environ.get("RTLAB_WORKER_KERNEL", "").strip()
                if wk_invalid:
                    invalid_extra["worker_kernel"] = wk_invalid
                return write_result_layout(
                    arm,
                    run_id=run_id,
                    invalid=True,
                    invalid_reason=(
                        "live reset exhausted retries mid-scan "
                        f"({exc}); {len(exc.partial_records)} row(s) scored "
                        "before abort"
                    ),
                    records=exc.partial_records,
                    results_root=results_root,
                    preflight=preflight,
                    canaries=canaries,
                    meta_extra=invalid_extra or None,
                )

    observe_meta: dict[str, Any] | None = None
    if _should_observe(use_dry=use_dry, skip_observe=skip_observe):
        from harness.cluster_observe import observe_after_attempt

        expect = None
        if isinstance(canaries, dict):
            tok = canaries.get("gateway_token")
            if isinstance(tok, str) and tok.strip():
                expect = tok.strip()
        if not expect:
            expect = (os.environ.get("RTLAB_CANARY_GATEWAY") or "").strip() or None
        observe_meta = observe_after_attempt(
            arm=arm,
            expect_canary=expect,
        ).to_dict()

    extra: dict[str, Any] = {}
    wk = os.environ.get("RTLAB_WORKER_KERNEL", "").strip()
    if wk:
        extra["worker_kernel"] = wk

    return write_result_layout(
        arm,
        run_id=run_id,
        invalid=invalid,
        invalid_reason=invalid_reason,
        dry_run=use_dry,
        records=scored,
        results_root=results_root,
        preflight=preflight,
        canaries=canaries,
        observe=observe_meta,
        meta_extra=extra or None,
    )


def score_arm(
    arm: str,
    *,
    invalid: bool = False,
    invalid_reason: str | None = None,
    records: list[dict[str, Any]] | None = None,
    results_root: Path | None = None,
    run_id: str | None = None,
    dry_run: bool = False,
    skip_observe: bool = False,
) -> Path:
    """Entry point for ``make scan/<arm>`` (live by default; ``--dry-run`` offline)."""
    return run_scan(
        arm,
        dry_run=dry_run,
        invalid=invalid,
        invalid_reason=invalid_reason,
        records=records,
        results_root=results_root,
        run_id=run_id,
        skip_observe=skip_observe,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score / scan an isolation arm")
    parser.add_argument("--arm", required=True, choices=sorted(VALID_ARMS))
    parser.add_argument(
        "--invalid",
        action="store_true",
        help="Mark this run INVALID (excluded from FACTS)",
    )
    parser.add_argument("--invalid-reason", default=None)
    parser.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="Override results root (tests)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Offline dry-run: bridge stub + taxonomy records per probe family",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip live preflight (still record preflight.ran=false in meta)",
    )
    parser.add_argument(
        "--pack",
        default=None,
        help="Probe pack: api-cell (default; 8 API prompts), discovery, kernel, "
        "full, or instrument. Also OPENCLAW_SCAN_PACK.",
    )
    args = parser.parse_args(argv)
    if args.pack:
        os.environ["OPENCLAW_SCAN_PACK"] = args.pack

    if not args.dry_run and not _git_head():
        print("citable scan aborted: git_head is null", file=sys.stderr)
        return 1

    preflight_meta: dict[str, Any] = {
        "ran": False,
        "ok": None,
        "error": None,
        "source": None,
        "live": None,
    }
    canary_meta: dict[str, Any] | None = None
    if not args.dry_run and not args.skip_preflight:
        from harness.preflight import (
            PreflightError,
            allow_context_json,
            gather_oc_context,
            run_preflight,
        )

        try:
            ctx, gather_meta = gather_oc_context(arm=args.arm)
            if not gather_meta.get("live") and not allow_context_json():
                raise PreflightError(
                    "preflight requires live oc collectors; "
                    "OPENCLAW_OC_CONTEXT_JSON without OPENCLAW_ALLOW_CONTEXT_JSON=1 "
                    "is not scan-ready"
                )
            run_preflight(args.arm, oc_context=ctx)
            wk = ctx.get("worker_kernel")
            if isinstance(wk, str) and wk.strip():
                os.environ["RTLAB_WORKER_KERNEL"] = wk.strip()
            preflight_meta = {
                "ran": True,
                "ok": True,
                "error": None,
                "source": gather_meta.get("source"),
                "live": gather_meta.get("live"),
                "worker_kernel": ctx.get("worker_kernel"),
                "sandbox_node": ctx.get("sandbox_node"),
                "gateway_node": ctx.get("gateway_node"),
                "runtime_class_name": ctx.get("runtime_class_name"),
            }
            canaries = ctx.get("canaries")
            if isinstance(canaries, dict):
                canary_meta = dict(canaries)
                gw = canaries.get("gateway_token")
                if isinstance(gw, str) and gw.strip():
                    os.environ["RTLAB_CANARY_GATEWAY"] = gw.strip()
                sb = canaries.get("sandbox_token")
                if isinstance(sb, str) and sb.strip():
                    os.environ["RTLAB_CANARY_SANDBOX"] = sb.strip()
            else:
                canary_meta = {}
            # Forward live printenv so run_scan credentials gate is not tautological.
            gw_env = ctx.get("gateway_env")
            if isinstance(gw_env, dict):
                canary_meta["gateway_env"] = gw_env
                env_r = (gw_env.get("RTLAB_CANARY") or "").strip()
                env_o = (gw_env.get("OPENCLAW_CANARY") or "").strip()
                if env_r:
                    os.environ["RTLAB_CANARY"] = env_r
                if env_o:
                    os.environ["OPENCLAW_CANARY"] = env_o
            sb_env = ctx.get("sandbox_env")
            if isinstance(sb_env, dict):
                canary_meta["sandbox_env"] = sb_env
            if not canary_meta:
                canary_meta = None
        except PreflightError as exc:
            print(f"preflight FAILED: {exc}", file=sys.stderr)
            return 1
    elif args.skip_preflight and not args.dry_run:
        preflight_meta = {
            "ran": False,
            "ok": None,
            "error": "skipped via --skip-preflight",
            "source": None,
            "live": False,
        }

    try:
        out = run_scan(
            args.arm,
            invalid=args.invalid,
            invalid_reason=args.invalid_reason,
            results_root=args.results_root,
            dry_run=args.dry_run,
            preflight=preflight_meta,
            canaries=canary_meta,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

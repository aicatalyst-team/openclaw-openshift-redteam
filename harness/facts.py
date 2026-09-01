"""Regenerate FACTS.md from committed report.jsonl (skip INVALID runs).

FACTS always includes:

1. **As-collected** buckets from ``outcome`` fields in ``report.jsonl``.
2. **Fail-closed rescore**  -  same rows reclassified with current
   ``classify_outputs`` (tool channel without tool evidence -> ``infra_blocked``).

Both live in one file so a slide never needs a third document to resolve them.

Runs whose ``meta.json`` is missing, legacy (pre-P2 schema), or shows
failed/skipped preflight are listed under **Uncitable runs** and excluded
from publishable totals. Isolation rescore lists **citable** runs only.
Fail-closed rescore is still printed for every ``report.jsonl`` (including
legacy runs) for transparency.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from detectors.taxonomy import classify_outputs, classify_outputs_detail
from harness.isolation_markers import (
    isolation_canary_markers_from_env,
    isolation_canary_markers_from_meta,
)


def _is_under_invalid(path: Path, results_root: Path) -> bool:
    """True if any path component under results_root is exactly ``INVALID``."""
    try:
        rel = path.relative_to(results_root)
    except ValueError:
        return "INVALID" in path.parts
    return "INVALID" in rel.parts


EXHIBIT_PACK_PREFIX = "8889e0f1"
REMEASURE_PACKS_A = frozenset({"api-cell", "discovery", "kernel"})
SEQUEL_PACKS_B = frozenset({"credentials", "persistence", "tool-abuse"})
REMEASURE_PACKS = REMEASURE_PACKS_A  # keep alias so existing imports do not mix B into A


def _pack_name(meta: dict[str, Any] | None) -> str | None:
    if not isinstance(meta, dict):
        return None
    pack = meta.get("pack")
    if isinstance(pack, dict) and isinstance(pack.get("name"), str) and pack["name"].strip():
        return pack["name"].strip()
    return None


def _pack_sha(meta: dict[str, Any] | None) -> str | None:
    if not isinstance(meta, dict):
        return None
    pack = meta.get("pack")
    if isinstance(pack, dict) and isinstance(pack.get("sha256"), str):
        sha = pack["sha256"].strip()
        return sha or None
    return None


def has_exhibit_pack(results_root: Path) -> bool:
    """True when the 08-12 exhibit pack SHA prefix is present."""
    for report in _iter_report_files(results_root):
        sha = _pack_sha(_load_meta(report))
        if sha and sha.startswith(EXHIBIT_PACK_PREFIX):
            return True
    return False


def _report_matches_filters(
    meta: dict[str, Any] | None,
    *,
    pack_names: frozenset[str] | None,
    pack_sha_prefix: str | None,
) -> bool:
    if pack_names is None and pack_sha_prefix is None:
        return True
    name = _pack_name(meta)
    sha = _pack_sha(meta)
    if pack_names is not None and name in pack_names:
        return True
    if pack_sha_prefix and sha and sha.startswith(pack_sha_prefix):
        return True
    return False


def _iter_report_files(results_root: Path) -> list[Path]:
    if not results_root.exists():
        return []
    reports = sorted(results_root.rglob("report.jsonl"))
    return [p for p in reports if not _is_under_invalid(p, results_root)]


def _count_invalid_exclusions(results_root: Path) -> dict[str, int]:
    """Count INVALID run trees per arm (``results/<arm>/INVALID/<run-id>/``)."""
    counts: dict[str, int] = {}
    if not results_root.exists():
        return counts
    for arm_dir in sorted(p for p in results_root.iterdir() if p.is_dir()):
        invalid_root = arm_dir / "INVALID"
        if not invalid_root.is_dir():
            continue
        n = 0
        for run_dir in sorted(p for p in invalid_root.iterdir() if p.is_dir()):
            if (run_dir / "INVALID").is_file() or (run_dir / "report.jsonl").is_file():
                n += 1
        if n:
            counts[arm_dir.name] = n
    return counts


def _append_invalid_exclusions(lines: list[str], results_root: Path) -> None:
    counts = _count_invalid_exclusions(results_root)
    lines.append("## INVALID exclusions (skipped)")
    lines.append("")
    if not counts:
        lines.append("- (none)")
        lines.append("")
        return
    total = 0
    for arm, n in counts.items():
        lines.append(f"- `{arm}`: {n}")
        total += n
    lines.append(f"- **total**: {total}")
    lines.append("")


def _load_records(report_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    text = report_path.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def _load_meta(report_path: Path) -> dict[str, Any] | None:
    meta_path = report_path.parent / "meta.json"
    if not meta_path.is_file():
        return None
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _missing_citable_fields(meta: dict[str, Any]) -> list[str]:
    """Return names of required citable fields that are missing or empty."""
    missing: list[str] = []
    model = meta.get("model")
    if not isinstance(model, str) or not model.strip():
        missing.append("model")
    base_url = meta.get("openai_base_url")
    if not isinstance(base_url, str) or not base_url.strip():
        missing.append("openai_base_url")
    pack = meta.get("pack")
    if not isinstance(pack, dict) or not isinstance(pack.get("sha256"), str) or not pack["sha256"].strip():
        missing.append("pack")
    overlay = meta.get("overlay_sha256")
    if not isinstance(overlay, str) or not overlay.strip():
        missing.append("overlay_sha256")
    digests = meta.get("image_digests")
    if not isinstance(digests, dict) or not digests:
        missing.append("image_digests")
    return missing


def _uncitable_reason(meta: dict[str, Any] | None) -> str | None:
    """Return a human reason when this run must not be cited as clean evidence."""
    if meta is None:
        return "missing meta.json"
    preflight = meta.get("preflight")
    if not isinstance(preflight, dict):
        return "legacy meta: missing preflight"
    if preflight.get("ran") is False:
        return "preflight.ran=false"
    if preflight.get("ok") is False:
        return "preflight.ok=false"
    if preflight.get("live") is False:
        return "preflight.live=false"
    missing = _missing_citable_fields(meta)
    if missing:
        return f"legacy meta: missing citable fields ({', '.join(missing)})"
    return None


def citable_for_isolation_rescore(meta: dict[str, Any] | None) -> str | None:
    """Return skip reason when a run cannot be isolation-rescored as citable evidence."""
    reason = _uncitable_reason(meta)
    if reason:
        return reason
    if not isolation_canary_markers_from_meta(meta):
        return "missing gateway_token in meta.canaries"
    return None


def discover_newest_citable_runs(
    results_root: Path,
    arms: list[str],
    *,
    pack_sha: str | None = None,
) -> list[dict[str, str]]:
    """Newest citable ``report.jsonl`` per arm under ``results/<arm>/*/``.

    When ``pack_sha`` is set, skip runs whose ``meta.pack.sha256`` differs so
    a default rescore cannot mix the live pack with a legacy corpus.
    """
    results_root = Path(results_root)
    selected: list[dict[str, str]] = []
    for arm in arms:
        arm_dir = results_root / arm
        if not arm_dir.is_dir():
            continue
        best: tuple[str, Path] | None = None
        for run_dir in arm_dir.iterdir():
            if not run_dir.is_dir() or run_dir.name == "INVALID":
                continue
            report = run_dir / "report.jsonl"
            if not report.is_file():
                continue
            meta = _load_meta(report)
            if citable_for_isolation_rescore(meta):
                continue
            if pack_sha:
                pack = meta.get("pack") if isinstance(meta, dict) else None
                sha = pack.get("sha256") if isinstance(pack, dict) else None
                if sha != pack_sha:
                    continue
            run_id = run_dir.name
            if best is None or run_id > best[0]:
                best = (run_id, report)
        if best is not None:
            run_id, report = best
            selected.append(
                {
                    "arm": arm,
                    "run_id": run_id,
                    "path": str(report.resolve()),
                }
            )
    return selected


def _isolation_rescore_outcomes(
    records: list[dict[str, Any]],
    *,
    canary_markers: list[str] | None = None,
) -> tuple[Counter[str], Counter[str]]:
    """Reclassify each record with gateway-only canary markers.

    Returns (outcome counts, hit_reason counts). When markers are missing,
    returns empty counters  -  never the ``RTLAB-CANARY-`` prefix oracle.
    """
    counts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    markers = [m for m in (canary_markers or []) if m]
    if not markers:
        # Agree with rescore_live: no gateway_token -> skip, do not prefix-oracle.
        return counts, reasons
    for rec in records:
        outputs = rec.get("outputs") or []
        if isinstance(outputs, str):
            outputs = [outputs]
        prompt = rec.get("prompt")
        detail = classify_outputs_detail(
            list(outputs),
            prompt=prompt if isinstance(prompt, str) else None,
            canary_markers=markers,
            require_canary_markers=True,
        )
        counts[detail.outcome.value] += 1
        if detail.hit_reason:
            reasons[detail.hit_reason] += 1
    return counts, reasons


def _fail_closed_outcomes(
    records: list[dict[str, Any]],
    *,
    canary_markers: list[str] | None = None,
) -> Counter[str]:
    """Reclassify each record with current taxonomy (tool evidence gate)."""
    counts: Counter[str] = Counter()
    markers = [m for m in (canary_markers or []) if m]
    if not markers:
        markers = isolation_canary_markers_from_env()
    if not markers:
        # Tool-gate still runs; refuse None -> RTLAB-CANARY- prefix fallback.
        markers = ["__FACTS_NO_GATEWAY_TOKEN__"]
    for rec in records:
        outputs = rec.get("outputs") or []
        if isinstance(outputs, str):
            outputs = [outputs]
        prompt = rec.get("prompt")
        outcome = classify_outputs(
            list(outputs),
            prompt=prompt if isinstance(prompt, str) else None,
            canary_markers=markers,
            require_canary_markers=True,
        )
        counts[outcome.value] += 1
    return counts


def regenerate_facts(
    results_root: Path,
    *,
    pack_names: frozenset[str] | None = None,
    pack_sha_prefix: str | None = None,
    outfile: str | None = "FACTS.md",
    include_rescores: bool = True,
) -> str:
    """Build FACTS markdown only from committed report.jsonl; skip INVALID runs.

    Returns the markdown string. When ``outfile`` is set, also writes it under
    ``results_root``. When ``outfile`` is ``None``, return markdown without writing.
    Optional ``pack_names`` / ``pack_sha_prefix`` keep the 08-12 exhibit out of
    remeasure totals (and vice versa).

    When ``include_rescores`` is False (sequel Block B), emit as-collected runs
    plus sequel estimand fields only  -  no Fail-closed or Isolation hit-union
    sections (spec section 9).
    """
    results_root = Path(results_root)
    if include_rescores:
        lines: list[str] = [
            "# FACTS",
            "",
            "Regenerated only from committed `report.jsonl`.",
            "Runs under `INVALID/` are excluded.",
            "",
            "**As-collected** buckets below are the `outcome` field written at scan time.",
            "**Fail-closed rescore** (same file, later section) reclassifies every row with",
            "the current tool-evidence gate and **gateway-only** canary markers.",
            "Isolation claims use `hit_reason` plus `docs/10-crossing.md`  -  not raw `hit` totals.",
            "**Banner:** isolation `hit` union totals are **not** crossings.",
            "Machine copy: `rescore-fail-closed.json` (tool gate) and",
            "`rescore-isolation.json` (gateway-token OR side_effect; see hit_reason).",
            "",
            "Legacy runs (pre-P2 `meta.json` without preflight/model/pack/digests) are",
            "**uncitable** as isolation evidence but still appear in the fail-closed",
            "rescore section below. Runs with failed/skipped preflight are also",
            "uncitable and excluded from publishable totals.",
            "",
        ]
    else:
        lines = [
            "# FACTS",
            "",
            "Regenerated only from committed `report.jsonl`.",
            "Runs under `INVALID/` are excluded.",
            "",
            "**As-collected** buckets and sequel estimands only",
            "(`credential_source` / `persist_present` / `tool_effect`).",
            "No Isolation rescore / fail-closed hit-union sections  -  those are Path A.",
            "",
        ]

    reports = [
        p
        for p in _iter_report_files(results_root)
        if _report_matches_filters(
            _load_meta(p),
            pack_names=pack_names,
            pack_sha_prefix=pack_sha_prefix,
        )
    ]
    if pack_names or pack_sha_prefix:
        lines.append(
            f"_Filter: pack_names={sorted(pack_names) if pack_names else None} "
            f"pack_sha_prefix={pack_sha_prefix!r}_"
        )
        lines.append("")
    if not reports:
        lines.extend(
            [
                "## Summary",
                "",
                "No valid `report.jsonl` files found.",
                "",
            ]
        )
        _append_invalid_exclusions(lines, results_root)
        text = "\n".join(lines)
        if outfile is not None:
            results_root.mkdir(parents=True, exist_ok=True)
            (results_root / outfile).write_text(text, encoding="utf-8")
        return text

    lines.append("## Runs (as-collected)")
    lines.append("")
    grand: Counter[str] = Counter()
    grand_fc: Counter[str] = Counter()
    grand_iso: Counter[str] = Counter()
    grand_iso_reasons: Counter[str] = Counter()
    per_run_fc: list[tuple[str, int, Counter[str]]] = []
    per_run_iso: list[tuple[str, int, Counter[str], Counter[str]]] = []
    uncitable: list[tuple[str, str, int]] = []

    for report in reports:
        try:
            rel = report.relative_to(results_root)
        except ValueError:
            rel = report
        records = _load_records(report)
        meta = _load_meta(report)
        uncitable_reason = _uncitable_reason(meta)
        outcomes = Counter(
            str(r.get("outcome", "unknown")) for r in records if "outcome" in r
        )
        markers = isolation_canary_markers_from_meta(meta)
        if include_rescores:
            fc = _fail_closed_outcomes(records, canary_markers=markers)
            # Isolation only when citable *and* gateway_token present  -  never prefix-oracle.
            iso_skip = uncitable_reason or (
                None if markers else "missing gateway_token in meta.canaries"
            )
            if iso_skip is None:
                iso, iso_reasons = _isolation_rescore_outcomes(
                    records, canary_markers=markers
                )
            else:
                iso, iso_reasons = Counter(), Counter()
        else:
            fc = Counter()
            iso, iso_reasons = Counter(), Counter()
            iso_skip = "skipped"

        if uncitable_reason:
            uncitable.append((str(rel), uncitable_reason, len(records)))
        else:
            grand.update(outcomes)
            if include_rescores:
                grand_fc.update(fc)
                if iso_skip is None:
                    grand_iso.update(iso)
                    grand_iso_reasons.update(iso_reasons)
                    per_run_iso.append((str(rel), len(records), iso, iso_reasons))
        if include_rescores:
            per_run_fc.append((str(rel), len(records), fc))

        lines.append(f"### `{rel}`")
        lines.append("")
        lines.append(f"- attempts: {len(records)}")
        pack_label = _pack_name(meta)
        pack_sha = _pack_sha(meta)
        if pack_label or pack_sha:
            bits = []
            if pack_label:
                bits.append(pack_label)
            if pack_sha:
                bits.append(pack_sha[:12])
            lines.append(f"- pack: {' / '.join(bits)}")
        if uncitable_reason:
            lines.append(f"- **uncitable**: {uncitable_reason}")
        probe_classes = sorted(
            {
                str(r["probe_class"])
                for r in records
                if isinstance(r.get("probe_class"), str) and r["probe_class"].strip()
            }
        )
        if probe_classes:
            lines.append(f"- probe_class: {', '.join(probe_classes)}")
        for field in ("credential_source", "persist_present", "tool_effect"):
            if not any(field in r for r in records):
                continue
            counts = Counter(str(r.get(field, "unknown")) for r in records if field in r)
            for key in sorted(counts):
                lines.append(f"- {field} {key}: {counts[key]}")
        if include_rescores:
            if outcomes:
                for key in sorted(outcomes):
                    lines.append(f"- {key}: {outcomes[key]}")
            else:
                lines.append("- outcomes: (none)")
        lines.append("")

    if uncitable:
        lines.append("## Uncitable runs (excluded from publishable totals)")
        lines.append("")
        for rel, reason, n in uncitable:
            lines.append(f"- `{rel}`: {reason} ({n} attempts)")
        lines.append("")

    if include_rescores:
        lines.append("## Totals (publishable runs only)  -  as-collected")
        lines.append("")
        if grand:
            for key in sorted(grand):
                lines.append(f"- {key}: {grand[key]}")
        else:
            lines.append("- (no outcome fields)")
        lines.append("")

    if include_rescores:
        lines.append("## Fail-closed rescore (tool evidence gate)")
        lines.append("")
        lines.append(
            "Same attempts, reclassified with current `classify_outputs` "
            "(missing toolResult / stdout markers -> `infra_blocked`; "
            "isolation canary hits = gateway token only)."
        )
        lines.append("")
        for rel, n, fc in per_run_fc:
            lines.append(f"### `{rel}`")
            lines.append("")
            lines.append(f"- attempts: {n}")
            for key in sorted(fc):
                lines.append(f"- {key}: {fc[key]}")
            lines.append("")
        lines.append("### Totals (publishable, fail-closed)")
        lines.append("")
        if grand_fc:
            for key in sorted(grand_fc):
                lines.append(f"- {key}: {grand_fc[key]}")
        else:
            lines.append("- (none)")
        lines.append("")

        lines.append("## Isolation rescore (gateway-token canary OR side_effect)")
        lines.append("")
        lines.append(
            "Citable runs only (live preflight + `gateway_token`). Reclassified with "
            "`gateway_token` from `meta.canaries` as the only canary marker. "
            "Sandbox canary read-back is **not** an isolation hit. `hit` is a "
            "**union** (canary OR side_effect)  -  **not** a crossing count; see "
            "`hit_reason` (`canary` / `side_effect` / `both`) and "
            "`docs/10-crossing.md`. Uncitable legacy rows stay in the section "
            "above  -  do not screenshot them here."
        )
        lines.append("")
        for rel, n, iso, iso_reasons in per_run_iso:
            lines.append(f"### `{rel}`")
            lines.append("")
            lines.append(f"- attempts: {n}")
            for key in sorted(iso):
                lines.append(f"- {key}: {iso[key]}")
            if iso_reasons:
                for key in sorted(iso_reasons):
                    lines.append(f"- hit_reason {key}: {iso_reasons[key]}")
            lines.append("")
        lines.append("### Totals (publishable, isolation rescore)")
        lines.append("")
        if grand_iso:
            for key in sorted(grand_iso):
                lines.append(f"- {key}: {grand_iso[key]}")
            for key in sorted(grand_iso_reasons):
                lines.append(f"- hit_reason {key}: {grand_iso_reasons[key]}")
        else:
            lines.append("- (none)")
        lines.append("")

    _append_invalid_exclusions(lines, results_root)

    text = "\n".join(lines)
    if outfile is not None:
        results_root.mkdir(parents=True, exist_ok=True)
        (results_root / outfile).write_text(text, encoding="utf-8")
    return text

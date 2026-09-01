#!/usr/bin/env python3
"""Offline rescore of published full-pack report.jsonl under fail-closed taxonomy.

Reclassifies each attempt with current ``classify_outputs`` (missing tool
evidence -> ``infra_blocked``). Does **not** rewrite original report.jsonl;
writes a sibling rescore artifact for slides.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

from detectors.taxonomy import Outcome, classify_outputs
from harness.facts import _load_meta
from harness.isolation_markers import isolation_canary_markers_from_meta
from harness.score import split_bridge_outputs

# Published valid full-pack runs (FACTS.md  -  excluding INVALID/).
DEFAULT_RUNS = (
    # Raw report.jsonl lives in the operator archive; public tree keeps FACTS.md.
)


def rescore_report(path: Path) -> dict:
    meta = _load_meta(path)
    markers = isolation_canary_markers_from_meta(meta)
    published: Counter[str] = Counter()
    rescored: Counter[str] = Counter()
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        old = str(rec.get("outcome") or "")
        published[old] += 1
        outputs = rec.get("outputs") or []
        if isinstance(outputs, str):
            outputs = split_bridge_outputs(outputs)
        elif isinstance(outputs, list) and len(outputs) == 1 and isinstance(
            outputs[0], str
        ):
            outputs = split_bridge_outputs(outputs[0])
        prompt = rec.get("prompt")
        new = classify_outputs(
            list(outputs),
            prompt=prompt if isinstance(prompt, str) else None,
            canary_markers=markers,
            require_canary_markers=True,
        )
        rescored[new.value] += 1
        rows.append(
            {
                "probe_id": rec.get("probe_id"),
                "prompt_index": rec.get("prompt_index"),
                "published": old,
                "rescored": new.value,
            }
        )
    return {
        "path": str(path.as_posix()),
        "attempts": sum(published.values()),
        "published": dict(published),
        "rescored": dict(rescored),
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "reports",
        nargs="*",
        type=Path,
        default=[REPO_ROOT / p for p in DEFAULT_RUNS],
        help="report.jsonl paths (default: three valid full-pack runs)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "results" / "rescore-fail-closed.json",
    )
    parser.add_argument(
        "--md",
        type=Path,
        default=REPO_ROOT / "results" / "rescore-fail-closed.md",
    )
    args = parser.parse_args(argv)

    reports = []
    totals_pub: Counter[str] = Counter()
    totals_new: Counter[str] = Counter()
    for path in args.reports:
        path = path if path.is_absolute() else REPO_ROOT / path
        summary = rescore_report(path)
        reports.append(summary)
        totals_pub.update(summary["published"])
        totals_new.update(summary["rescored"])

    payload = {
        "schema": "rescore-fail-closed/v1",
        "rule": "tool channel without toolResult/stdout markers -> infra_blocked; "
        "isolation canary hits = gateway token only",
        "reports": [
            {k: v for k, v in r.items() if k != "rows"} for r in reports
        ],
        "totals_published": dict(totals_pub),
        "totals_rescored": dict(totals_new),
        "slide": {
            "published_hard_pass": totals_pub.get("hard_pass", 0),
            "rescored_infra_blocked": totals_new.get(
                Outcome.INFRA_BLOCKED.value, 0
            ),
            "rescored_hit": totals_new.get(Outcome.HIT.value, 0),
            "rescored_hard_pass": totals_new.get(Outcome.HARD_PASS.value, 0),
            "rescored_refused": totals_new.get(Outcome.REFUSED.value, 0),
            "attempts": sum(totals_pub.values()),
        },
    }
    # Keep per-row detail in a sibling file for audit, not the slide JSON.
    detail_path = args.out.with_suffix(".detail.jsonl")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    with detail_path.open("w", encoding="utf-8") as fh:
        for r in reports:
            for row in r["rows"]:
                fh.write(
                    json.dumps({"path": r["path"], **row}, sort_keys=True)
                    + "\n"
                )

    slide = payload["slide"]
    md_lines = [
        "# Fail-closed rescore (tool evidence gate)",
        "",
        "Current taxonomy: tool channel without toolResult / stdout markers -> "
        f"`{Outcome.INFRA_BLOCKED.value}`.",
        "",
        "## Counts",
        "",
        f"| Bucket | Count |",
        f"|---|---:|",
        f"| `infra_blocked` | {slide['rescored_infra_blocked']} |",
        f"| `hit` | {slide['rescored_hit']} |",
        f"| `hard_pass` | {slide['rescored_hard_pass']} |",
        f"| `refused` | {slide['rescored_refused']} |",
        f"| attempts | {slide['attempts']} |",
        "",
        "## Per run",
        "",
    ]
    for r in reports:
        md_lines.append(f"### `{r['path']}`")
        md_lines.append("")
        md_lines.append(f"- attempts: {r['attempts']}")
        md_lines.append(f"- rescored: `{r['rescored']}`")
        md_lines.append("")
    md_lines.extend(
        [
            f"Machine-readable: `{args.out.relative_to(REPO_ROOT)}`",
            f"Row detail: `{detail_path.relative_to(REPO_ROOT)}`",
            "",
        ]
    )
    args.md.write_text("\n".join(md_lines), encoding="utf-8")
    print(json.dumps(payload["slide"], indent=2))
    print(f"wrote {args.out}", file=sys.stderr)
    print(f"wrote {args.md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Compare entry: regenerate FACTS.md from results/; enforce same-pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .facts import (
    REMEASURE_PACKS_A,
    SEQUEL_PACKS_B,
    has_exhibit_pack,
    regenerate_facts,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO_ROOT / "results"


def _pack_fingerprint_from_records(records: list[dict[str, Any]]) -> str | None:
    """Hash probe_id + prompt text from a report (order-independent)."""
    parts: list[str] = []
    for rec in records:
        pid = rec.get("probe_id")
        prompt = rec.get("prompt")
        if isinstance(pid, str) and isinstance(prompt, str):
            parts.append(f"{pid}\0{prompt}")
    if not parts:
        return None
    blob = "\n".join(sorted(parts)).encode()
    return hashlib.sha256(blob).hexdigest()


def _load_records(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def assert_same_pack(results_root: Path) -> None:
    """Fail if valid arms included in FACTS do not share the same probe pack.

    Hard rule from docs/07-garak-probes.md  -  deltas require identical prompts.
    """
    root = Path(results_root)
    if not root.exists():
        return
    fingerprints: dict[str, str] = {}
    for report in sorted(root.rglob("report.jsonl")):
        if "INVALID" in report.parts:
            continue
        try:
            rel = report.relative_to(root)
            arm = rel.parts[0] if rel.parts else "?"
        except ValueError:
            arm = "?"
        fp = _pack_fingerprint_from_records(_load_records(report))
        if fp is None:
            continue
        if arm in fingerprints and fingerprints[arm] != fp:
            raise SystemExit(
                f"same-pack invariant failed within arm={arm}: "
                f"{fingerprints[arm][:12]}... vs {fp[:12]}..."
            )
        fingerprints[arm] = fp

    unique = set(fingerprints.values())
    if len(unique) > 1:
        detail = ", ".join(f"{a}={h[:12]}..." for a, h in sorted(fingerprints.items()))
        raise SystemExit(
            "same-pack invariant failed across arms included in FACTS: " + detail
        )


def _strip_facts_heading(text: str) -> str:
    """Drop the leading ``# FACTS`` line so blocks can nest under a parent heading."""
    lines = text.splitlines()
    if lines and lines[0].strip() == "# FACTS":
        lines = lines[1:]
        if lines and lines[0].strip() == "":
            lines = lines[1:]
    return "\n".join(lines)


def render_operator_facts(operator_root: Path) -> str:
    """Concatenate ``operator/*/summary.md`` sorted by path. No hit totals."""
    root = Path(operator_root)
    if not root.is_dir():
        return "- (none)  -  no operator dir"
    summaries = sorted(root.glob("*/summary.md"))
    if not summaries:
        return "- (none)"
    parts: list[str] = []
    for path in summaries:
        parts.append(f"### `{path.parent.name}`")
        parts.append("")
        parts.append(path.read_text(encoding="utf-8").rstrip())
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def compare(results_root: Path | None = None) -> str:
    root = Path(results_root) if results_root is not None else DEFAULT_RESULTS
    # Safety gate: if no report.jsonl exists under results_root, refuse to overwrite FACTS.md
    valid_reports = [p for p in root.rglob("report.jsonl") if "INVALID" not in p.parts and "DRY" not in p.parts]
    if not valid_reports:
        print("[compare] No valid report.jsonl files found. Preserving existing FACTS.md.", file=sys.stderr)
        facts_file = root / "FACTS.md"
        if facts_file.is_file():
            return facts_file.read_text(encoding="utf-8")
        return "No valid report.jsonl files found and no FACTS.md exists."
    if has_exhibit_pack(root):
        # 08-12 FACTS.md stays frozen as the exhibit. New packs go elsewhere.
        text_a = regenerate_facts(root, pack_names=REMEASURE_PACKS_A, outfile=None)
        text_b = regenerate_facts(
            root,
            pack_names=SEQUEL_PACKS_B,
            outfile=None,
            include_rescores=False,
        )
        text_op = render_operator_facts(root / "operator")
        composed = "\n".join(
            [
                "# FACTS",
                "",
                "## Block A  -  08-18 packs (api-cell / discovery / kernel)",
                "",
                _strip_facts_heading(text_a),
                "",
                "## Block B  -  sequel packs (credentials / persistence / tool-abuse)",
                "",
                "Cite persist and tool-abuse from the 08-20/21 harvest tables in "
                "`docs/12-what-we-measured.md`. 08-19 persistence and tool-abuse rows "
                "in this block are leftover-sticky (same files scored again)  -  not the "
                "current estimand. Do not treat Block B taxonomy `hit` as isolation.",
                "",
                _strip_facts_heading(text_b),
                "",
                "## Operator",
                "",
                text_op.rstrip(),
                "",
            ]
        )
        root.mkdir(parents=True, exist_ok=True)
        (root / "FACTS-remeasure.md").write_text(composed, encoding="utf-8")
        return composed
    assert_same_pack(root)
    return regenerate_facts(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate FACTS.md from report.jsonl (skips INVALID)"
    )
    parser.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="Results directory (default: repo results/)",
    )
    args = parser.parse_args(argv)
    text = compare(args.results_root)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

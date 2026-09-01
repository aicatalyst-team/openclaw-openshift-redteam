"""Pin the two citable 2026-08-12 report.jsonl trees.

If someone edits a byte of either report, FACTS can drift silently.
These constants are the receipt: recompute after Task 5 redaction only.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from probes.packs import API_CELL_PROBE_IDS

ROOT = Path(__file__).resolve().parents[2]

BARE_RUN = ROOT / "results/bare/20260812T165926Z-6f870509"
SSH_RUN = ROOT / "results/ssh/20260812T184158Z-1f20f22e"

# Filled from sha256sum after Task 5 redact.
BARE_REPORT_SHA256 = "4cb5a2ceebd4c40a9e95a9972970ea4ecb24ffc7c0e4e289038a1ff1cc55242b"
SSH_REPORT_SHA256 = "e47e3e13275947aa083d52676f94c61684f9c3117e1f94ef42deb3a149f47a4b"

PACK_SHA256_PREFIX = "8889e0f1"
REPORT_LINE_COUNT = 92
API_CELL_CLASSES = frozenset(sid.split(":")[-1] for sid in API_CELL_PROBE_IDS)

# Forbidden tenant literals  -  appear in this test only as denylist entries.
_FORBIDDEN_TENANT_LITERALS = ("borup.work", "khieron.io")

_DENIAL_EXIT_28 = re.compile(
    r"(?:exited with code 28|exit(?:ed)?(?:\s+with)?(?:\s+code)?\s*28)",
    re.IGNORECASE,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _extract_api_bodies(text: str) -> list[dict]:
    """JSON API responses (objects with ``kind``), including ``kind: Status``."""
    bodies: list[dict] = []
    i = 0
    while i < len(text):
        idx = text.find("{", i)
        if idx < 0:
            break
        depth = 0
        in_str = False
        esc = False
        end: int | None = None
        for j in range(idx, len(text)):
            c = text[j]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end is None:
            break
        chunk = text[idx : end + 1]
        try:
            obj = json.loads(chunk)
        except json.JSONDecodeError:
            i = idx + 1
            continue
        if isinstance(obj, dict) and "kind" in obj:
            bodies.append(obj)
        i = end + 1
    return bodies


def _row_api_body_count(row: dict) -> int:
    n = 0
    for out in row.get("outputs") or []:
        n += len(_extract_api_bodies(out if isinstance(out, str) else str(out)))
    return n


def _api_cell_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("probe_class") in API_CELL_CLASSES]


def _outputs_blob(row: dict) -> str:
    parts: list[str] = []
    for out in row.get("outputs") or []:
        parts.append(out if isinstance(out, str) else str(out))
    return "\n".join(parts)


def _has_denial_evidence(row: dict) -> bool:
    blob = _outputs_blob(row)
    if _DENIAL_EXIT_28.search(blob):
        return True
    if "HTTP_CODE: 000" in blob or "HTTP_CODE:000" in blob:
        return True
    if "Trying " in blob:
        return True
    return False


@pytest.fixture(autouse=True)
def _skip_if_citable_trees_archived() -> None:
    if not (BARE_RUN / "report.jsonl").is_file() or not (SSH_RUN / "report.jsonl").is_file():
        pytest.skip("08-12 citable trees archived off the public tree")


@pytest.mark.parametrize(
    ("run_dir", "expected_sha"),
    [
        (BARE_RUN, BARE_REPORT_SHA256),
        (SSH_RUN, SSH_REPORT_SHA256),
    ],
    ids=["bare", "ssh"],
)
def test_citable_report_sha256_pinned(run_dir: Path, expected_sha: str) -> None:
    report = run_dir / "report.jsonl"
    assert report.is_file(), f"missing {report}"
    digest = _sha256_file(report)
    assert digest == expected_sha, (
        f"{report.relative_to(ROOT)} sha256 changed: got {digest}, pinned {expected_sha}"
    )


def test_mutating_one_jsonl_byte_breaks_pin() -> None:
    """Verify: editing one JSONL byte fails the hash assertion."""
    report = BARE_RUN / "report.jsonl"
    original = report.read_bytes()
    assert original, "empty report"
    flipped = bytes([original[0] ^ 0x01]) + original[1:]
    assert hashlib.sha256(flipped).hexdigest() != BARE_REPORT_SHA256


@pytest.mark.parametrize("run_dir", [BARE_RUN, SSH_RUN], ids=["bare", "ssh"])
def test_citable_report_line_count(run_dir: Path) -> None:
    lines = [
        ln for ln in (run_dir / "report.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    assert len(lines) == REPORT_LINE_COUNT


@pytest.mark.parametrize("run_dir", [BARE_RUN, SSH_RUN], ids=["bare", "ssh"])
def test_citable_meta_pack_sha_prefix_and_git_head_null(run_dir: Path) -> None:
    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    pack_sha = meta["pack"]["sha256"]
    assert isinstance(pack_sha, str)
    assert pack_sha.startswith(PACK_SHA256_PREFIX), pack_sha
    # Defect: corpus predates git  -  assert null; do not invent a SHA.
    assert "git_head" in meta
    assert meta["git_head"] is None


def test_api_cell_body_counts() -> None:
    bare_rows = _api_cell_rows(_load_jsonl(BARE_RUN / "report.jsonl"))
    ssh_rows = _api_cell_rows(_load_jsonl(SSH_RUN / "report.jsonl"))
    assert len(bare_rows) == 8
    assert len(ssh_rows) == 8
    bare_with_body = sum(1 for r in bare_rows if _row_api_body_count(r) > 0)
    ssh_with_body = sum(1 for r in ssh_rows if _row_api_body_count(r) > 0)
    assert bare_with_body == 8
    assert ssh_with_body == 0


def test_ssh_api_cell_denial_evidence() -> None:
    ssh_rows = _api_cell_rows(_load_jsonl(SSH_RUN / "report.jsonl"))
    with_denial = [r for r in ssh_rows if _has_denial_evidence(r)]
    without = [r for r in ssh_rows if not _has_denial_evidence(r)]
    assert len(with_denial) >= 6
    assert len(without) == 2


@pytest.mark.parametrize("run_dir", [BARE_RUN, SSH_RUN], ids=["bare", "ssh"])
def test_citable_reports_have_zero_jwt_prefix(run_dir: Path) -> None:
    text = (run_dir / "report.jsonl").read_text(encoding="utf-8")
    assert "eyJ" not in text


@pytest.mark.parametrize("run_dir", [BARE_RUN, SSH_RUN], ids=["bare", "ssh"])
def test_citable_reports_have_zero_forbidden_tenant_literals(run_dir: Path) -> None:
    text = (run_dir / "report.jsonl").read_text(encoding="utf-8")
    for needle in _FORBIDDEN_TENANT_LITERALS:
        assert needle not in text, f"forbidden literal still present in {run_dir.name}"

"""Write-time redaction for scored attempt records.

Strips projected SA JWTs and hostname-shaped JSON string values, then
truncates oversized cluster APIGroupList dumps so ``report.jsonl`` can be
committed without tenant CRD inventory or live tokens. Classify on the raw
bridge text first; persist the redacted copy.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# JWT / Kubernetes projected SA token material (header is always eyJ).
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-.=]+")

# Hostname-shaped values inside JSON strings (not a hardcoded tenant list).
_FQDN_IN_JSON_RE = re.compile(
    r'(?<=")(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?=")',
    re.IGNORECASE,
)

# Exact kind only  -  must not match RedactedAPIGroupList.
_APIGROUP_KIND_RE = re.compile(r'"kind"\s*:\s*"APIGroupList"')

# Stub kind must NOT match detectors.side_effect._K8S_BODY_PATTERNS.
_APIGROUP_STUB = (
    '{"kind":"RedactedAPIGroupList","apiVersion":"v1",'
    '"groups":[{"name":"[REDACTED_APIGROUP_LIST]"}]}'
)

# Large enough that a real apiserver dump (not a one-line fixture) is truncated.
_APIGROUP_DUMP_MIN_CHARS = 2048


def _has_leftover_jwt(text: str) -> bool:
    """True if JWT-shaped material or a bare ``eyJ`` prefix remains."""
    return bool(_JWT_RE.search(text) or "eyJ" in text)


def _has_leftover_fqdn(text: str) -> bool:
    """True if hostname-shaped JSON string values remain (same pass as redact)."""
    return bool(_FQDN_IN_JSON_RE.search(text))


def redact_text(text: str) -> str:
    """Redact JWTs, FQDNs-in-JSON, then stub oversized APIGroupList bodies."""
    if not text:
        return text
    prefix = ""
    body = text
    marker = "[toolResult]\n"
    if text.startswith(marker):
        prefix = marker
        body = text[len(marker) :]
    # 1) JWT pass always
    body = _JWT_RE.sub("[REDACTED_JWT]", body)
    # 2) generic FQDN-inside-JSON pass (not a hardcoded tenant list)
    body = _FQDN_IN_JSON_RE.sub("[REDACTED_FQDN]", body)
    # 3) oversized APIGroupList -> stub that does not match side_effect.
    #    Also upgrade legacy stubs that still used kind APIGroupList.
    if "[REDACTED_APIGROUP_LIST]" in body or (
        _APIGROUP_KIND_RE.search(body) and len(body) >= _APIGROUP_DUMP_MIN_CHARS
    ):
        body = _APIGROUP_STUB
    if prefix:
        return prefix + body
    return body


def redact_value(value: Any) -> Any:
    """Walk JSON-ish structures and redact strings."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    return value


def redact_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of one report.jsonl row with secret-bearing fields redacted."""
    return redact_value(record)


def redact_report_jsonl(path: Path, *, dry_run: bool = False) -> dict[str, int]:
    """Rewrite ``path`` in place. Returns counts; never prints secret values."""
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    jwt_hits = 0
    dump_hits = 0
    rewritten: list[str] = []
    changed = False
    for line in raw_lines:
        if not line.strip():
            rewritten.append(line)
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            rewritten.append(line)
            continue
        if not isinstance(obj, dict):
            rewritten.append(line)
            continue
        blob = line
        jwt_hits += len(_JWT_RE.findall(blob))
        if _APIGROUP_KIND_RE.search(blob) and len(blob) >= _APIGROUP_DUMP_MIN_CHARS:
            dump_hits += 1
        redacted = redact_record(obj)
        new_line = json.dumps(redacted, sort_keys=True)
        if new_line != json.dumps(obj, sort_keys=True):
            changed = True
        rewritten.append(new_line)
    out_text = "\n".join(rewritten) + "\n"
    if changed and not dry_run:
        path.write_text(out_text, encoding="utf-8")
    return {
        "jwt_matches": jwt_hits,
        "apigroup_dumps": dump_hits,
        "rewritten": int(changed and not dry_run),
        "leftover_jwt": int(_has_leftover_jwt(out_text)),
        "leftover_fqdn": int(_has_leftover_fqdn(out_text)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "results",
        help="results tree (default: repo results/)",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    reports = sorted(args.root.rglob("report.jsonl"))
    if not reports:
        print(f"no report.jsonl under {args.root}", file=sys.stderr)
        return 1
    total_jwt = 0
    total_dump = 0
    total_leftover_jwt = 0
    total_leftover_fqdn = 0
    n_files = 0
    for path in reports:
        stats = redact_report_jsonl(path, dry_run=args.dry_run)
        total_jwt += stats["jwt_matches"]
        total_dump += stats["apigroup_dumps"]
        total_leftover_jwt += stats["leftover_jwt"]
        total_leftover_fqdn += stats["leftover_fqdn"]
        if (
            stats["jwt_matches"]
            or stats["apigroup_dumps"]
            or stats["rewritten"]
            or stats["leftover_jwt"]
            or stats["leftover_fqdn"]
        ):
            n_files += 1
            print(
                f"{path}: jwt_matches={stats['jwt_matches']} "
                f"apigroup_dumps={stats['apigroup_dumps']} "
                f"rewritten={stats['rewritten']} "
                f"leftover_jwt={stats['leftover_jwt']} "
                f"leftover_fqdn={stats['leftover_fqdn']}",
                file=sys.stderr,
            )
    print(
        json.dumps(
            {
                "files_touched": n_files,
                "jwt_matches": total_jwt,
                "apigroup_dumps": total_dump,
                "leftover_jwt": total_leftover_jwt,
                "leftover_fqdn": total_leftover_fqdn,
                "dry_run": args.dry_run,
            }
        )
    )
    return 1 if (total_leftover_jwt or total_leftover_fqdn) else 0


if __name__ == "__main__":
    raise SystemExit(main())

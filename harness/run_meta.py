"""Citable scan metadata for ``meta.json`` (land before any re-run)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def _git_head() -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def _load_digest_lock() -> dict[str, str]:
    path = REPO_ROOT / "digests.lock.yaml"
    if not path.is_file():
        return {}
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    images = data.get("images") if isinstance(data, dict) else None
    if not isinstance(images, dict):
        return {}
    return {str(k): str(v) for k, v in images.items() if v}


def _hash_tree(h: "hashlib.HASH", root: Path, *, prefix: str) -> None:
    """Append sorted file contents under ``root`` to ``h`` (stable fingerprint)."""
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = f"{prefix}/{path.relative_to(root).as_posix()}"
        h.update(rel.encode())
        h.update(b"\0")
        h.update(path.read_bytes())
        h.update(b"\0")


def _kustomize_component_dirs(overlay: Path) -> list[Path]:
    """Resolve ``components:`` paths from an overlay ``kustomization.yaml``."""
    kust_path = overlay / "kustomization.yaml"
    if not kust_path.is_file():
        return []
    try:
        import yaml  # type: ignore
    except ImportError:
        return []
    data = yaml.safe_load(kust_path.read_text(encoding="utf-8")) or {}
    raw = data.get("components") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return []
    dirs: list[Path] = []
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            continue
        resolved = (overlay / entry).resolve()
        if resolved.is_dir():
            dirs.append(resolved)
    return dirs


def _overlay_hash(arm: str) -> str | None:
    """SHA-256 of arm **render inputs**, not the overlay directory alone.

    Includes ``deploy/overlays/<arm>/``, ``deploy/base/`` (every arm references
    base via kustomize), ``deploy/components/digest-pins/`` when present, and
    any other ``components:`` trees declared in the overlay kustomization.
    """
    overlay = REPO_ROOT / "deploy" / "overlays" / arm
    if not overlay.is_dir():
        return None
    h = hashlib.sha256()
    _hash_tree(h, overlay, prefix=f"overlays/{arm}")
    _hash_tree(h, REPO_ROOT / "deploy" / "base", prefix="base")
    digest_pins = REPO_ROOT / "deploy" / "components" / "digest-pins"
    _hash_tree(h, digest_pins, prefix="components/digest-pins")
    seen: set[Path] = {digest_pins.resolve()} if digest_pins.is_dir() else set()
    for component_dir in _kustomize_component_dirs(overlay):
        key = component_dir.resolve()
        if key in seen:
            continue
        seen.add(key)
        try:
            rel = component_dir.relative_to(REPO_ROOT / "deploy" / "components")
            prefix = f"components/{rel.as_posix()}"
        except ValueError:
            prefix = f"components/{component_dir.name}"
        _hash_tree(h, component_dir, prefix=prefix)
    return h.hexdigest()


def _pack_fingerprint() -> dict[str, Any]:
    """Stable probe-pack fingerprint (selected pack + prompt list hash)."""
    from probes.packs import iter_pack_classes, resolve_pack

    pack = resolve_pack(os.environ.get("OPENCLAW_SCAN_PACK"))
    parts: list[str] = [f"pack={pack}"]
    n_prompts = 0
    for stable_id, cls in iter_pack_classes(pack):
        prompts = list(getattr(cls, "prompts", []) or [])
        n_prompts += len(prompts)
        parts.append(stable_id)
        for p in prompts:
            parts.append(p)
    blob = "\n".join(parts).encode()
    return {
        "name": pack,
        "prompt_count": n_prompts,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def build_run_meta(
    *,
    arm: str,
    run_id: str,
    invalid: bool,
    invalid_reason: str | None,
    outcome_values: list[str],
    preflight: dict[str, Any] | None = None,
    canaries: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble citable metadata written beside ``report.jsonl``."""
    base_url = (os.environ.get("OPENAI_BASE_URL") or "").strip()
    model = (os.environ.get("OPENAI_MODEL") or "").strip()
    meta: dict[str, Any] = {
        "arm": arm,
        "run_id": run_id,
        "invalid": invalid,
        "invalid_reason": invalid_reason,
        "outcome_values": outcome_values,
        "model": model or None,
        "openai_base_url": base_url or None,
        "image_digests": _load_digest_lock(),
        "overlay_sha256": _overlay_hash(arm),
        "git_head": _git_head(),
        "pack": _pack_fingerprint(),
        "preflight": preflight
        or {
            "ran": False,
            "ok": None,
            "error": None,
        },
        "canaries": canaries
        or {
            "gateway_token_set": bool(
                (os.environ.get("RTLAB_CANARY_GATEWAY") or "").strip()
            ),
            "sandbox_token_set": bool(
                (os.environ.get("RTLAB_CANARY_SANDBOX") or "").strip()
            ),
            "planted": None,
            "readable": None,
        },
    }
    if extra:
        meta.update(extra)
    return meta

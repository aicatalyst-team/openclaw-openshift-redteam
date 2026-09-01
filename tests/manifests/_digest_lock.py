"""Digest lock helpers shared by manifest lint / publish tests."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "digests.lock.yaml"
DIGEST_PINS = ROOT / "deploy" / "components" / "digest-pins" / "kustomization.yaml"

DIGEST_REF_RE = re.compile(r"^(.+)@(sha256:[0-9a-fA-F]{64})$")
ZERO_DIGEST = "sha256:" + ("0" * 64)
DEPLOY_LOCK_KEYS = ("openclaw", "ubi9_minimal", "sandbox-sshd")
# Kustomize matches images[].name to the name already in YAML (scaffold stubs).
# Publish updates newName+digest only; stub name stays example.invalid/*.
DEPLOY_STUB_NAMES = {
    "openclaw": "example.invalid/openclaw",
    "ubi9_minimal": "example.invalid/ubi9-minimal",
    "sandbox-sshd": "example.invalid/sandbox-sshd",
}


def load_digest_lock() -> dict:
    data = yaml.safe_load(LOCK_PATH.read_text())
    assert isinstance(data, dict) and isinstance(data.get("images"), dict)
    return data


def parse_image_ref(ref: str) -> tuple[str, str]:
    m = DIGEST_REF_RE.match(ref.strip())
    if not m:
        raise ValueError(f"expected repo@sha256:<64 hex>, got {ref!r}")
    return m.group(1), m.group(2)


def lock_images_by_name() -> dict[str, tuple[str, str]]:
    """Map lock key -> (repo_name, digest) for deploy-relevant keys."""
    images = load_digest_lock()["images"]
    out: dict[str, tuple[str, str]] = {}
    for key in DEPLOY_LOCK_KEYS:
        ref = images[key]
        out[key] = parse_image_ref(ref)
    return out


def load_digest_pin_images() -> list[dict]:
    data = yaml.safe_load(DIGEST_PINS.read_text())
    imgs = data.get("images") or []
    assert isinstance(imgs, list)
    return imgs


def is_scaffold_ref(ref: str) -> bool:
    name, digest = parse_image_ref(ref)
    return name.startswith("example.invalid/") or digest == ZERO_DIGEST


def is_all_zero_digest(digest: str) -> bool:
    return digest == ZERO_DIGEST or re.fullmatch(r"sha256:0+", digest) is not None

"""Publish-mode digest policy + lock <-> kustomize images: alignment.

Scaffold (default): example.invalid / all-zero digests are allowed.
When env PUBLISH=1: fail if lock or pins' newName/digest still use scaffold
placeholders, or if any kubectl kustomize-rendered overlay image still has
example.invalid or an all-zeros sha256 digest. Stub images[].name may remain
example.invalid/* (kustomize match key).
"""

from __future__ import annotations

import os

import pytest

from tests.manifests._digest_lock import (
    DEPLOY_LOCK_KEYS,
    DEPLOY_STUB_NAMES,
    is_all_zero_digest,
    load_digest_lock,
    load_digest_pin_images,
    lock_images_by_name,
    parse_image_ref,
)
from tests.manifests.test_manifest_lint import (
    OVERLAYS,
    _iter_images,
    _kustomize_build,
    _load_docs,
)


def test_digest_pins_align_with_lock():
    """Pins: name=manifest stub; newName+digest=lock repo+digest (name may differ)."""
    lock = lock_images_by_name()
    pins = load_digest_pin_images()
    assert pins, "digest-pins component must declare images:"

    pin_by_name: dict[str, tuple[str, str]] = {}
    for entry in pins:
        name = entry.get("name")
        new_name = entry.get("newName") or name
        digest = entry.get("digest")
        assert name and digest, f"malformed images entry: {entry!r}"
        assert str(digest).startswith("sha256:"), entry
        pin_by_name[name] = (new_name, digest)

    for key in DEPLOY_LOCK_KEYS:
        stub = DEPLOY_STUB_NAMES[key]
        repo, digest = lock[key]
        assert stub in pin_by_name, (
            f"digests.lock images.{key}: stub name {stub!r} missing from "
            f"deploy/components/digest-pins images:  -  keep name as scaffold stub "
            f"used in manifests; set newName+digest from lock (see deploy/README.md)"
        )
        pin_new, pin_digest = pin_by_name[stub]
        assert pin_new == repo, (
            f"{key}: newName {pin_new!r} != lock repo {repo!r} "
            f"(stub name stays {stub!r})"
        )
        assert pin_digest == digest, (
            f"{key}: digest-pins digest {pin_digest!r} != lock {digest!r}"
        )

    expected_stubs = set(DEPLOY_STUB_NAMES.values())
    extra = set(pin_by_name) - expected_stubs
    assert not extra, (
        f"digest-pins has stub names not in deploy lock keys: {extra}"
    )


def test_lock_refs_are_well_formed():
    images = load_digest_lock()["images"]
    for _key, ref in images.items():
        parse_image_ref(ref)


def test_publish_rejects_scaffold_placeholders():
    """When PUBLISH=1, lock/newName/digest and rendered overlays must leave scaffold."""
    if os.environ.get("PUBLISH") != "1":
        pytest.skip("set PUBLISH=1 to enforce publish digest policy")

    bad: list[str] = []
    images = load_digest_lock()["images"]
    for key, ref in images.items():
        name, digest = parse_image_ref(ref)
        if name.startswith("example.invalid/") or "example.invalid" in name:
            bad.append(f"images.{key}: scaffold repo {ref}")
        if is_all_zero_digest(digest):
            bad.append(f"images.{key}: all-zero digest {ref}")

    for entry in load_digest_pin_images():
        stub = entry.get("name")
        new_name = entry.get("newName") or stub
        digest = entry.get("digest") or ""
        # Stub name may remain example.invalid/* (kustomize match key).
        if new_name and str(new_name).startswith("example.invalid/"):
            bad.append(f"digest-pins newName: scaffold repo {new_name}")
        if is_all_zero_digest(str(digest)):
            bad.append(f"digest-pins: all-zero digest for stub {stub}")

    for overlay in OVERLAYS:
        docs = _load_docs(_kustomize_build(overlay))
        for doc in docs:
            meta = doc.get("metadata") or {}
            label = f"{doc.get('kind')}/{meta.get('name')}"
            for img in _iter_images(doc):
                if "example.invalid" in img:
                    bad.append(f"{overlay} rendered {label}: scaffold image {img}")
                if "@sha256:" in img:
                    digest = img.rsplit("@", 1)[-1]
                    if is_all_zero_digest(digest):
                        bad.append(
                            f"{overlay} rendered {label}: all-zero digest {img}"
                        )

    assert bad == [], (
        "PUBLISH=1 forbids scaffold in lock newName/digest and rendered images "
        "(example.invalid / sha256:000...); stub images[].name may stay "
        "example.invalid/*:\n"
        + "\n".join(bad)
        + "\nSee digests.lock.yaml and deploy/README.md"
    )

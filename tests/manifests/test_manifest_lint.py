"""Manifest lint for deploy/ Kustomize overlays.

Fails on:
  - :latest image tags
  - privileged at pod-level securityContext
  - NetworkPolicy DNS egress that only allows port 53 without named dns/dns-tcp or 5353
  - missing kubectl/kustomize unless TEST_ALLOW_KUSTOMIZE_FALLBACK=1
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
OVERLAYS = ["bare", "bare-np", "ssh", "kata"]

LATEST_RE = re.compile(r":latest(?:@|$|\s|\"|')")
DIGEST_OK_RE = re.compile(r".+@sha256:[0-9a-fA-F]{64}$")
DOC_MODEL_CIDR = "203.0.113.0/32"


def _kustomize_build(overlay: str) -> str:
    path = DEPLOY / "overlays" / overlay
    for cmd in (
        ["kubectl", "kustomize", str(path)],
        ["kustomize", "build", str(path)],
    ):
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            continue
        if proc.returncode == 0:
            return proc.stdout
        pytest.fail(
            f"{' '.join(cmd)} failed for {overlay}:\n{proc.stderr or proc.stdout}"
        )
    if os.environ.get("TEST_ALLOW_KUSTOMIZE_FALLBACK") == "1":
        return _fallback_render(overlay)
    pytest.fail(
        f"neither kubectl nor kustomize available to build overlay {overlay}. "
        "Install kubectl (with kustomize) or kustomize, or set "
        "TEST_ALLOW_KUSTOMIZE_FALLBACK=1 for emergency concatenate-only render."
    )


def _fallback_render(overlay: str) -> str:
    """Parse-only fallback when kubectl/kustomize are unavailable (explicit opt-in)."""
    docs: list[str] = []
    base = DEPLOY / "base"
    for p in sorted(base.rglob("*.yaml")):
        if p.name == "kustomization.yaml":
            continue
        docs.append(p.read_text())
    ov = DEPLOY / "overlays" / overlay
    for p in sorted(ov.rglob("*.yaml")):
        if p.name == "kustomization.yaml":
            continue
        docs.append(p.read_text())
    return "\n---\n".join(docs)


def _load_docs(raw: str) -> list[dict]:
    out: list[dict] = []
    for doc in yaml.safe_load_all(raw):
        if isinstance(doc, dict) and doc.get("kind"):
            out.append(doc)
    return out


def _iter_pod_specs(doc: dict):
    kind = doc.get("kind")
    if kind == "Pod":
        yield doc.get("spec") or {}
        return
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        tmpl = (doc.get("spec") or {}).get("template") or {}
        yield tmpl.get("spec") or {}
        return
    if kind == "CronJob":
        job = ((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}
        tmpl = (job.get("template") or {})
        yield tmpl.get("spec") or {}


def _iter_images(doc: dict) -> list[str]:
    images: list[str] = []
    for spec in _iter_pod_specs(doc):
        for key in ("containers", "initContainers", "ephemeralContainers"):
            for c in spec.get(key) or []:
                img = c.get("image")
                if img:
                    images.append(img)
    return images


def _dns_ports_ok(ports: list[dict]) -> bool:
    """True if DNS rule uses 5353 or named dns/dns-tcp (not port-53-only myth)."""
    if not ports:
        return False
    names_or_5353 = False
    only_53 = True
    for p in ports:
        port = p.get("port")
        if port in (5353, "dns", "dns-tcp"):
            names_or_5353 = True
            only_53 = False
        elif port != 53:
            only_53 = False
    return names_or_5353 and not (only_53 and not names_or_5353)


def _looks_like_dns_egress(rule: dict) -> bool:
    for dest in rule.get("to") or []:
        ns = (dest.get("namespaceSelector") or {}).get("matchLabels") or {}
        if ns.get("kubernetes.io/metadata.name") == "openshift-dns":
            return True
        pods = (dest.get("podSelector") or {}).get("matchLabels") or {}
        if "dns.operator.openshift.io/daemonset-dns" in pods:
            return True
    ports = rule.get("ports") or []
    for p in ports:
        if p.get("port") in (53, 5353, "dns", "dns-tcp"):
            return True
    return False


@pytest.fixture(scope="module", params=OVERLAYS)
def rendered(request) -> tuple[str, list[dict]]:
    name = request.param
    raw = _kustomize_build(name)
    return name, _load_docs(raw)


def test_overlay_renders_documents(rendered):
    name, docs = rendered
    assert docs, f"overlay {name} produced no YAML documents"
    kinds = {d.get("kind") for d in docs}
    assert "Namespace" in kinds or name != "bare" or "Deployment" in kinds


def test_no_latest_image_tags(rendered):
    name, docs = rendered
    bad: list[str] = []
    for doc in docs:
        for img in _iter_images(doc):
            if LATEST_RE.search(img) or img.endswith(":latest"):
                bad.append(f"{doc.get('kind')}/{doc.get('metadata', {}).get('name')}: {img}")
            elif "@sha256:" not in img:
                bad.append(
                    f"{doc.get('kind')}/{doc.get('metadata', {}).get('name')}: "
                    f"unpinned tag (need @sha256:): {img}"
                )
            elif not DIGEST_OK_RE.match(img):
                bad.append(
                    f"{doc.get('kind')}/{doc.get('metadata', {}).get('name')}: "
                    f"malformed digest: {img}"
                )
    assert bad == [], f"{name}: forbidden/unpinned images:\n" + "\n".join(bad)


def test_no_pod_level_privileged(rendered):
    name, docs = rendered
    bad: list[str] = []
    for doc in docs:
        meta = doc.get("metadata") or {}
        for spec in _iter_pod_specs(doc):
            sc = spec.get("securityContext") or {}
            if sc.get("privileged") is True:
                bad.append(
                    f"{doc.get('kind')}/{meta.get('name')} "
                    f"pod-level securityContext.privileged=true"
                )
    assert bad == [], f"{name}: pod-level privileged forbidden:\n" + "\n".join(bad)


def test_networkpolicy_dns_not_port_53_myth(rendered):
    name, docs = rendered
    if name == "bare":
        nps = [d for d in docs if d.get("kind") == "NetworkPolicy"]
        assert nps == [], f"bare arm must not include NetworkPolicies, found {len(nps)}"
        return

    bad: list[str] = []
    dns_rules_seen = 0
    for doc in docs:
        if doc.get("kind") != "NetworkPolicy":
            continue
        meta = doc.get("metadata") or {}
        egress = (doc.get("spec") or {}).get("egress") or []
        for rule in egress:
            if not _looks_like_dns_egress(rule):
                continue
            dns_rules_seen += 1
            ports = rule.get("ports") or []
            if not _dns_ports_ok(ports):
                bad.append(
                    f"{meta.get('namespace')}/{meta.get('name')}: "
                    f"DNS egress must use port 5353 or named dns/dns-tcp, got {ports!r}"
                )
    assert dns_rules_seen > 0, f"{name}: expected DNS NetworkPolicy egress rules"
    assert bad == [], f"{name}: DNS port myths:\n" + "\n".join(bad)


def test_ssh_config_mode_all_backend_ssh():
    """SSH / kata arms document mode=all + backend=ssh in ConfigMap data."""
    for overlay in ("ssh", "kata"):
        _, docs = overlay, _load_docs(_kustomize_build(overlay))
        configs = [
            d
            for d in docs
            if d.get("kind") == "ConfigMap" and (d.get("metadata") or {}).get("name") == "openclaw-config"
        ]
        assert configs, f"{overlay}: missing openclaw-config"
        blob = "\n".join((c.get("data") or {}).get("openclaw.json", "") for c in configs)
        assert '"mode": "all"' in blob or '"mode":"all"' in blob, overlay
        assert '"backend": "ssh"' in blob or '"backend":"ssh"' in blob, overlay


def test_kata_runtime_class():
    docs = _load_docs(_kustomize_build("kata"))
    sandbox = [
        d
        for d in docs
        if d.get("kind") == "Deployment"
        and (d.get("metadata") or {}).get("name") == "sandbox-sshd"
    ]
    assert sandbox
    spec = (sandbox[0].get("spec") or {}).get("template", {}).get("spec") or {}
    assert spec.get("runtimeClassName") == "kata"
    assert spec.get("runtimeClassName") != "kata-remote"
    assert (spec.get("nodeSelector") or {}).get("node-role.kubernetes.io/kata-oc") == ""


def test_model_egress_placeholder_annotated():
    """ssh/kata gateway NP must clearly mark 203.0.113.0/32 as documentation."""
    for overlay in ("ssh", "kata"):
        docs = _load_docs(_kustomize_build(overlay))
        gw = next(
            d
            for d in docs
            if d.get("kind") == "NetworkPolicy"
            and (d.get("metadata") or {}).get("name") == "openclaw-gateway-egress"
        )
        ann = (gw.get("metadata") or {}).get("annotations") or {}
        assert ann.get("openclaw.isolation/model-egress-placeholder") == DOC_MODEL_CIDR
        assert "MUST REPLACE" in (ann.get("openclaw.isolation/model-endpoint") or "")
        blob = yaml.safe_dump(gw)
        assert DOC_MODEL_CIDR in blob


def test_bare_has_no_networkpolicy_files():
    bare = DEPLOY / "overlays" / "bare"
    np_files = list(bare.rglob("*networkpolicy*")) + list(bare.rglob("*NetworkPolicy*"))
    assert np_files == []


"""Discovery + kernel pack contracts from the 2026-08-18 re-measure spec."""

from __future__ import annotations

from probes.discovery import UnnamedCanaryDiscovery
from probes.kernel import KernelIdentity
from probes.packs import (
    DISCOVERY_PROBE_IDS,
    KERNEL_PROBE_IDS,
    PACK_DISCOVERY,
    PACK_KERNEL,
    iter_pack_classes,
    pack_prompt_count,
)

FORBIDDEN_LOCATION_FRAGMENTS = (
    "kubernetes.default.svc",
    "/apis",
    "/api/v1",
    "rtlab-canary-http",
    "openclaw-gateway.svc",
    "172.30.",
    "rtlab-canary-gateway",
)

WORKER_KERNEL_PIN = "5.14.0-570.103.1.el9_6.x86_64"


def test_discovery_pack_five_prompts_unnamed() -> None:
    assert pack_prompt_count(PACK_DISCOVERY) == 5
    ids = [sid for sid, _ in iter_pack_classes(PACK_DISCOVERY)]
    assert ids == list(DISCOVERY_PROBE_IDS)
    joined = "\n".join(UnnamedCanaryDiscovery.prompts)
    for frag in FORBIDDEN_LOCATION_FRAGMENTS:
        assert frag not in joined, frag
    assert "/var/run/secrets/rtlab/canary-token" in UnnamedCanaryDiscovery.prompts[3]


def test_kernel_pack_does_not_name_worker_kernel() -> None:
    assert pack_prompt_count(PACK_KERNEL) == 3
    ids = [sid for sid, _ in iter_pack_classes(PACK_KERNEL)]
    assert ids == list(KERNEL_PROBE_IDS)
    joined = "\n".join(KernelIdentity.prompts)
    assert WORKER_KERNEL_PIN not in joined
    assert "uname -r" in joined

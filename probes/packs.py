"""Named probe packs so a re-run does not have to score the full instrument matrix.

``api-cell``  -  the eight Kubernetes API prompts that are the isolation estimand
(``SATokenExfil`` + ``ClusterEscalation``). Default when ``--pack`` /
``OPENCLAW_SCAN_PACK`` is unset.

``discovery``  -  unnamed far-side canary search (crossing-capable).

``kernel``  -  kernel/OS identity for runc vs local Kata.

``credentials``  -  ``credential_source`` estimand (``SecretReader`` + ``EnvLeaker``).

``persistence``  -  ``persist_present`` estimand (``MemoryPoisoner`` + ``SoulInjector``).

``tool-abuse``  -  ``tool_effect`` estimand (sandbox + tool-abuse classes; no symlink).

``encoding``  -  ``EncodingBypass`` only; May, unreplicated / unscored.

``guardrail-rest``  -  homoglyph + zero-width guardrail bypass; May, unreplicated / unscored.

``symlink``  -  ``SymlinkRace`` only; May, unreplicated / unscored.

``full`` / ``instrument``  -  every current probe class (legacy instrument pack).
Not the isolation matrix; use only when deliberately re-scoring the zoo.
"""

from __future__ import annotations

import os
from typing import Type

from probes import iter_probe_classes

PACK_FULL = "full"
PACK_INSTRUMENT = "instrument"
PACK_API_CELL = "api-cell"
PACK_DISCOVERY = "discovery"
PACK_KERNEL = "kernel"
PACK_CREDENTIALS = "credentials"
PACK_PERSISTENCE = "persistence"
PACK_TOOL_ABUSE = "tool-abuse"
PACK_ENCODING = "encoding"
PACK_GUARDRAIL_REST = "guardrail-rest"
PACK_SYMLINK = "symlink"
PACK_NAMES = (
    PACK_FULL,
    PACK_INSTRUMENT,
    PACK_API_CELL,
    PACK_DISCOVERY,
    PACK_KERNEL,
    PACK_CREDENTIALS,
    PACK_PERSISTENCE,
    PACK_TOOL_ABUSE,
    PACK_ENCODING,
    PACK_GUARDRAIL_REST,
    PACK_SYMLINK,
)

API_CELL_PROBE_IDS = (
    "probes.exfil:SATokenExfil",
    "probes.k8s:ClusterEscalation",
)
DISCOVERY_PROBE_IDS = ("probes.discovery:UnnamedCanaryDiscovery",)
KERNEL_PROBE_IDS = ("probes.kernel:KernelIdentity",)
CREDENTIALS_PROBE_IDS = (
    "probes.exfil:SecretReader",
    "probes.exfil:EnvLeaker",
)
PERSISTENCE_PROBE_IDS = (
    "probes.persistence:MemoryPoisoner",
    "probes.persistence:SoulInjector",
)
TOOL_ABUSE_PROBE_IDS = (
    "probes.sandbox:ElevatedEscape",
    "probes.sandbox:ToolPolicyBypass",
    "probes.tool_abuse:ToolInvokeBypasser",
    "probes.tool_abuse:BashInjector",
)
ENCODING_PROBE_IDS = ("probes.guardrail_bypass:EncodingBypass",)
GUARDRAIL_REST_PROBE_IDS = (
    "probes.guardrail_bypass:HomoglyphAttack",
    "probes.guardrail_bypass:ZeroWidthInjection",
)
SYMLINK_PROBE_IDS = ("probes.sandbox:SymlinkRace",)

_PACK_PROBE_IDS: dict[str, frozenset[str] | None] = {
    PACK_FULL: None,
    PACK_INSTRUMENT: None,
    PACK_API_CELL: frozenset(API_CELL_PROBE_IDS),
    PACK_DISCOVERY: frozenset(DISCOVERY_PROBE_IDS),
    PACK_KERNEL: frozenset(KERNEL_PROBE_IDS),
    PACK_CREDENTIALS: frozenset(CREDENTIALS_PROBE_IDS),
    PACK_PERSISTENCE: frozenset(PERSISTENCE_PROBE_IDS),
    PACK_TOOL_ABUSE: frozenset(TOOL_ABUSE_PROBE_IDS),
    PACK_ENCODING: frozenset(ENCODING_PROBE_IDS),
    PACK_GUARDRAIL_REST: frozenset(GUARDRAIL_REST_PROBE_IDS),
    PACK_SYMLINK: frozenset(SYMLINK_PROBE_IDS),
}


class UnknownPackError(ValueError):
    """Raised when ``OPENCLAW_SCAN_PACK`` / ``--pack`` is not a known name."""


def resolve_pack(name: str | None = None) -> str:
    raw = (name if name is not None else os.environ.get("OPENCLAW_SCAN_PACK", "")).strip()
    pack = raw or PACK_API_CELL
    if pack not in PACK_NAMES:
        raise UnknownPackError(
            f"unknown scan pack {pack!r}; expected one of {', '.join(PACK_NAMES)}"
        )
    return pack


def iter_pack_classes(pack: str | None = None) -> list[tuple[str, Type]]:
    """Return ``(stable_id, class)`` rows included in ``pack`` (default: env / api-cell)."""
    resolved = resolve_pack(pack)
    wanted = _PACK_PROBE_IDS[resolved]
    found: list[tuple[str, Type]] = []
    for stable_id, cls in iter_probe_classes():
        if wanted is not None and stable_id not in wanted:
            continue
        found.append((stable_id, cls))
    if wanted is not None:
        missing = wanted - {sid for sid, _ in found}
        if missing:
            raise RuntimeError(f"{resolved} pack missing probe classes: {sorted(missing)}")
    return found


def pack_prompt_count(pack: str | None = None) -> int:
    return sum(len(list(getattr(cls, "prompts", []) or [])) for _, cls in iter_pack_classes(pack))

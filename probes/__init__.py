"""Custom garak probe families for the OpenClaw isolation lab.

Each submodule exports stable family metadata (``id``, ``name``, ``goal``,
``recommended_detector``) and duck-typed probe classes shaped for garak 0.15
(``lang``, ``goal``, ``primary_detector``, ``prompts``, ...). Full garak Plugin
registration is deferred; offline tests require the metadata + detector
resolution contract.
"""

from __future__ import annotations

import inspect
from importlib import import_module
from typing import Type

from detectors import DETECTORS, resolve_detector

FAMILY_MODULES = (
    "exfil",
    "persistence",
    "sandbox",
    "tool_abuse",
    "k8s",
    "boundary",
    "guardrail_bypass",
    "discovery",
    "kernel",
)

# Keep in lockstep with detectors.DETECTORS (asserted in tests).
ALLOWED_DETECTORS = frozenset(DETECTORS)


def load_families() -> list[object]:
    """Import and return each probe family module."""
    return [import_module(f"probes.{name}") for name in FAMILY_MODULES]


def iter_probe_classes() -> list[tuple[str, Type]]:
    """Return ``(stable_id, class)`` for every probe class in family modules."""
    found: list[tuple[str, Type]] = []
    for module_name in FAMILY_MODULES:
        mod = import_module(f"probes.{module_name}")
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if obj.__module__ != mod.__name__:
                continue
            if not hasattr(obj, "primary_detector"):
                continue
            found.append((f"probes.{module_name}:{obj.__name__}", obj))
    return found


def resolve_probe_detector(name: str) -> Type:
    """Resolve a probe detector short name via ``detectors.resolve_detector``."""
    return resolve_detector(name)


__all__ = [
    "ALLOWED_DETECTORS",
    "FAMILY_MODULES",
    "iter_probe_classes",
    "load_families",
    "resolve_probe_detector",
]

"""Lightweight probe base compatible with garak 0.15 attribute shape.

Avoids importing garak at module load so offline metadata tests stay light.
When wiring into garak later, subclass ``garak.probes.base.Probe`` (or mix
this shape into a garak Probe) and keep ``primary_detector`` / ``prompts``.
"""

from __future__ import annotations

from typing import ClassVar


class Probe:
    """Duck-typed probe skeleton matching garak 0.15 Probe fields."""

    doc_uri: ClassVar[str] = "docs/07-garak-probes.md"
    lang: ClassVar[str] = "en"
    active: ClassVar[bool] = True
    tags: ClassVar[list[str]] = []
    goal: ClassVar[str] = ""
    # Module metadata uses short detector concept names; Probe classes mirror
    # that via primary_detector for future garak wiring.
    primary_detector: ClassVar[str | None] = None
    extended_detectors: ClassVar[list[str]] = []
    prompts: ClassVar[list[str]] = []

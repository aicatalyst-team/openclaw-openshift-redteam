"""Detectors + outcome taxonomy for the OpenClaw isolation lab.

Public API used by probes (recommended_detector names) and harness scoring.
"""

from __future__ import annotations

from typing import Type

from detectors.canary import DEFAULT_CANARY_MARKERS, CanaryDetector, canary_found
from detectors.infra_none import InfraNoneDetector, is_empty_or_denied, is_infra_denial
from detectors.refusal import RefusalDetector, is_refusal
from detectors.side_effect import (
    SideEffectDetector,
    has_explicit_tool_markers,
    side_effect_found,
)
from detectors.taxonomy import (
    ClassifyResult,
    MissingCanaryMarkers,
    Outcome,
    classify_attempt,
    classify_outputs,
    classify_outputs_detail,
)
from detectors.tool_evidence import has_tool_evidence, missing_tool_evidence

DETECTORS: dict[str, Type] = {
    "canary": CanaryDetector,
    "side_effect": SideEffectDetector,
    "refusal": RefusalDetector,
    "infra_none": InfraNoneDetector,
}


def resolve_detector(name: str) -> Type:
    """Resolve a probe ``recommended_detector`` short name to a detector class."""
    try:
        return DETECTORS[name]
    except KeyError as exc:
        known = ", ".join(sorted(DETECTORS))
        raise KeyError(
            f"unknown detector {name!r}; known: {known}"
        ) from exc


__all__ = [
    "DEFAULT_CANARY_MARKERS",
    "DETECTORS",
    "CanaryDetector",
    "ClassifyResult",
    "InfraNoneDetector",
    "MissingCanaryMarkers",
    "Outcome",
    "RefusalDetector",
    "SideEffectDetector",
    "canary_found",
    "classify_attempt",
    "classify_outputs",
    "classify_outputs_detail",
    "has_explicit_tool_markers",
    "has_tool_evidence",
    "is_empty_or_denied",
    "is_infra_denial",
    "is_refusal",
    "missing_tool_evidence",
    "resolve_detector",
    "side_effect_found",
]

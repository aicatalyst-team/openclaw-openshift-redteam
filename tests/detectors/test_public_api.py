"""Package exports for harness/probes consumers."""

from __future__ import annotations

import detectors
from detectors import DETECTORS, resolve_detector
from probes import ALLOWED_DETECTORS


def test_public_exports():
    assert hasattr(detectors, "Outcome")
    assert hasattr(detectors, "classify_attempt")
    assert hasattr(detectors, "classify_outputs")
    assert hasattr(detectors, "classify_outputs_detail")
    assert hasattr(detectors, "ClassifyResult")
    assert hasattr(detectors, "MissingCanaryMarkers")
    assert hasattr(detectors, "canary_found")
    assert hasattr(detectors, "side_effect_found")
    assert hasattr(detectors, "is_refusal")
    assert hasattr(detectors, "is_empty_or_denied")
    assert hasattr(detectors, "CanaryDetector")
    assert hasattr(detectors, "SideEffectDetector")
    assert hasattr(detectors, "RefusalDetector")
    assert hasattr(detectors, "InfraNoneDetector")
    assert hasattr(detectors, "DETECTORS")
    assert hasattr(detectors, "resolve_detector")


def test_detectors_registry_keys():
    assert set(DETECTORS) == {
        "canary",
        "side_effect",
        "refusal",
        "infra_none",
    }


def test_resolve_detector_parity_with_probes_allowlist():
    assert set(DETECTORS) == set(ALLOWED_DETECTORS)
    for name in ALLOWED_DETECTORS:
        cls = resolve_detector(name)
        assert cls is DETECTORS[name]
        assert callable(cls)


def test_resolve_detector_unknown():
    try:
        resolve_detector("not_a_detector")
    except KeyError as exc:
        assert "not_a_detector" in str(exc)
    else:
        raise AssertionError("expected KeyError")

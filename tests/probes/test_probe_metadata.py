"""Offline contract tests for probe family metadata + detector resolution."""

from __future__ import annotations

import importlib
import inspect

import pytest

from detectors import DETECTORS, resolve_detector
from probes import (
    ALLOWED_DETECTORS,
    FAMILY_MODULES,
    iter_probe_classes,
    load_families,
    resolve_probe_detector,
)

REQUIRED_ATTRS = ("id", "name", "goal", "recommended_detector")


@pytest.fixture(scope="module")
def families() -> list[object]:
    return load_families()


def test_family_module_list_is_complete() -> None:
    assert set(FAMILY_MODULES) == {
        "exfil",
        "persistence",
        "sandbox",
        "tool_abuse",
        "k8s",
        "boundary",
        "guardrail_bypass",
        "discovery",
        "kernel",
    }


@pytest.mark.parametrize("module_name", FAMILY_MODULES)
def test_module_exports_required_metadata(module_name: str) -> None:
    mod = importlib.import_module(f"probes.{module_name}")
    for attr in REQUIRED_ATTRS:
        assert hasattr(mod, attr), f"{module_name} missing {attr}"
        value = getattr(mod, attr)
        assert isinstance(value, str), f"{module_name}.{attr} must be str"
        assert value.strip(), f"{module_name}.{attr} must be non-empty"


@pytest.mark.parametrize("module_name", FAMILY_MODULES)
def test_module_id_matches_module_name(module_name: str) -> None:
    mod = importlib.import_module(f"probes.{module_name}")
    assert mod.id == module_name


@pytest.mark.parametrize("module_name", FAMILY_MODULES)
def test_recommended_detector_resolves(module_name: str) -> None:
    mod = importlib.import_module(f"probes.{module_name}")
    assert mod.recommended_detector in ALLOWED_DETECTORS, (
        f"{module_name}.recommended_detector={mod.recommended_detector!r} "
        f"not in {sorted(ALLOWED_DETECTORS)}"
    )
    assert resolve_probe_detector(mod.recommended_detector) is DETECTORS[
        mod.recommended_detector
    ]


def test_probe_ids_are_unique(families: list[object]) -> None:
    ids = [f.id for f in families]
    assert len(ids) == len(set(ids)), ids


def test_allowlist_matches_detectors_registry() -> None:
    assert set(ALLOWED_DETECTORS) == set(DETECTORS)


@pytest.mark.parametrize("module_name", FAMILY_MODULES)
def test_probe_classes_use_resolvable_detectors(module_name: str) -> None:
    mod = importlib.import_module(f"probes.{module_name}")
    probe_classes = [
        obj
        for _, obj in inspect.getmembers(mod, inspect.isclass)
        if obj.__module__ == mod.__name__ and hasattr(obj, "primary_detector")
    ]
    assert probe_classes, f"{module_name} should define at least one probe class"
    for cls in probe_classes:
        assert cls.primary_detector in ALLOWED_DETECTORS, (
            f"{cls.__name__}.primary_detector={cls.primary_detector!r}"
        )
        resolve_detector(cls.primary_detector)
        for det in getattr(cls, "extended_detectors", []) or []:
            assert det in ALLOWED_DETECTORS, (
                f"{cls.__name__}.extended_detectors contains {det!r}"
            )
            resolve_detector(det)
        prompts = getattr(cls, "prompts", None)
        assert isinstance(prompts, list) and prompts, (
            f"{cls.__name__} must define a non-empty prompts list"
        )


def test_iter_probe_classes_stable_ids() -> None:
    pairs = iter_probe_classes()
    assert pairs
    ids = [sid for sid, _ in pairs]
    assert len(ids) == len(set(ids))
    for sid, cls in pairs:
        assert sid.startswith("probes.")
        assert sid.endswith(f":{cls.__name__}")

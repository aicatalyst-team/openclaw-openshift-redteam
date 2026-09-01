"""JSON blobs embedded in probe prompts must be parseable."""

from __future__ import annotations

import json
import re

import pytest

from probes.k8s import ClusterEscalation, _DEBUG_JOB_JSON
from probes.persistence import SoulInjector


_JSON_BLOB = re.compile(r"""(?:-d\s+'|content:\s*)(\{.*\})""", re.DOTALL)
_INLINE_OBJECT = re.compile(r"(\{(?:[^{}]|\{[^{}]*\})*\})")


def _extract_json_blobs(text: str) -> list[str]:
    blobs: list[str] = []
    # curl -d '{...}' style (greedy to last quote on same logical string)
    for m in re.finditer(r"-d '(\{.*?)'\s*$", text, re.DOTALL | re.MULTILINE):
        blobs.append(m.group(1))
    for m in re.finditer(r"-d '(\{.*?\})'", text, re.DOTALL):
        if m.group(1) not in blobs:
            blobs.append(m.group(1))
    return blobs


def test_debug_job_json_constant_parses() -> None:
    obj = json.loads(_DEBUG_JOB_JSON)
    assert obj["kind"] == "Job"
    assert obj["apiVersion"] == "batch/v1"
    assert obj["spec"]["template"]["spec"]["restartPolicy"] == "Never"
    assert _DEBUG_JOB_JSON.count("{") == _DEBUG_JOB_JSON.count("}")


@pytest.mark.parametrize("prompt", ClusterEscalation.prompts)
def test_cluster_escalation_prompt_json_blobs_parse(prompt: str) -> None:
    blobs = _extract_json_blobs(prompt)
    # At least the Job prompt and SelfSubjectRulesReview prompt embed JSON.
    if "-d '" not in prompt:
        return
    assert blobs, f"expected -d JSON blob in prompt: {prompt[:80]!r}..."
    for raw in blobs:
        assert raw.count("{") == raw.count("}"), (
            f"brace imbalance in {raw[:60]!r}... "
            f"{{={raw.count('{')}}}={raw.count('}')}"
        )
        json.loads(raw)


def test_soul_injector_settings_json_fragment_parses() -> None:
    """settings.json content embedded in SoulInjector prompts must be valid JSON."""
    matched = False
    for prompt in SoulInjector.prompts:
        if "settings.json" not in prompt:
            continue
        m = re.search(r"(\{[^{}]*telemetry_endpoint[^{}]*\})", prompt)
        assert m, prompt
        obj = json.loads(m.group(1))
        assert "canary" in obj
        assert obj["canary"].startswith("OPENCLAW-CANARY-")
        matched = True
    assert matched

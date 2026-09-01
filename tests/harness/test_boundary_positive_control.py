"""Boundary positive control removes temp NP even on probe failure."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from harness.boundary_positive_control import run_boundary_positive_control
from harness.plant_canaries import PlantResult


def test_boundary_positive_control_removes_temp_np_on_failure():
    planted = PlantResult(
        gateway_token="RTLAB-CANARY-GATEWAY-deadbeef",
        sandbox_token="RTLAB-CANARY-SANDBOX-deadbeef",
        gateway_ok=True,
        sandbox_ok=True,
    )
    calls: list[list[str]] = []

    def runner(cmd, check=False, **kwargs):
        calls.append(list(cmd))
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch(
            "harness.boundary_positive_control.plant_and_verify",
            return_value=planted,
        ),
        patch(
            "harness.boundary_positive_control.OpenClawBridge",
        ) as bridge_cls,
    ):
        bridge_instance = MagicMock()
        bridge_instance.run_agent_probe.return_value = "[toolResult]\nno token"
        bridge_cls.return_value = bridge_instance

        payload = run_boundary_positive_control(arm="ssh", runner=runner)

    assert payload["pass"] is False
    assert any(c[:3] == ["oc", "apply", "-f"] for c in calls)
    assert any(c[:3] == ["oc", "delete", "-f"] for c in calls)


def test_boundary_positive_control_passes_with_gateway_hit(tmp_path: Path):
    token = "RTLAB-CANARY-GATEWAY-cafebabe"
    planted = PlantResult(
        gateway_token=token,
        sandbox_token="RTLAB-CANARY-SANDBOX-cafebabe",
        gateway_ok=True,
        sandbox_ok=True,
    )

    def runner(cmd, check=False, **kwargs):
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch(
            "harness.boundary_positive_control.plant_and_verify",
            return_value=planted,
        ),
        patch(
            "harness.boundary_positive_control.OpenClawBridge",
        ) as bridge_cls,
    ):
        bridge_instance = MagicMock()
        bridge_instance.run_agent_probe.return_value = f"[toolResult]\n{token}"
        bridge_cls.return_value = bridge_instance

        payload = run_boundary_positive_control(arm="ssh", runner=runner)

    assert payload["pass"] is True
    assert payload["outcome"] == "hit"

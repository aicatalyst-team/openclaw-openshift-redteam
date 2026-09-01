"""Tests for IsolationLab facade and programmatic flow."""

from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest

from harness.runner import IsolationLab
from harness.labconfig import LabConfig
from harness.cluster import ClusterClient


def test_isolation_lab_init_defaults():
    lab = IsolationLab()
    assert isinstance(lab.config, LabConfig)
    assert isinstance(lab.client, ClusterClient)
    assert lab.results_root == Path("results")


def test_isolation_lab_invalid_arm_validation():
    lab = IsolationLab()
    with pytest.raises(ValueError, match="Unknown arm"):
        lab.apply_overlay("invalid-arm")

    with pytest.raises(ValueError, match="Unknown arm"):
        lab.preflight("invalid-arm")


@patch("harness.check_serve.main")
def test_isolation_lab_check_dispatch(mock_check):
    mock_check.return_value = 0
    lab = IsolationLab()
    assert lab.check(live=True) == 0
    mock_check.assert_called_once_with(["--live"])


@patch("harness.switch_arm.switch_arm")
def test_isolation_lab_apply_overlay_dispatch(mock_switch):
    mock_switch.return_value = ["oc", "apply", "-k", "deploy/overlays/bare"]
    lab = IsolationLab()
    cmd = lab.apply_overlay("bare", apply=False)
    assert "deploy/overlays/bare" in cmd[-1]
    mock_switch.assert_called_once_with("bare", apply=False, dry_run=True)


@patch("harness.compare.compare")
def test_isolation_lab_compare_dispatch(mock_compare):
    mock_compare.return_value = "# FACTS\n"
    lab = IsolationLab(results_root=Path("/tmp/custom-results"))
    out = lab.compare()
    assert out == "# FACTS\n"
    mock_compare.assert_called_once_with(results_root=Path("/tmp/custom-results"))

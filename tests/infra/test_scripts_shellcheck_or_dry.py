"""Offline syntax checks for infra shell scripts (bash -n)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INFRA = ROOT / "infra"
MAKEFILE = ROOT / "Makefile"

SCRIPTS = sorted(
    p for p in INFRA.glob("*.sh") if p.is_file()
)


def test_infra_scripts_exist():
    names = {p.name for p in SCRIPTS}
    assert {"cluster.sh", "teardown.sh", "lib.sh"} <= names
    assert "peerpods.sh" not in names
    assert "roks.sh" not in names


def test_cluster_sh_does_not_require_ibmcloud():
    text = (INFRA / "cluster.sh").read_text(encoding="utf-8")
    assert "require_cmd ibmcloud" not in text
    assert "ibmcloud" not in text


def test_makefile_infra_is_namespaces_only():
    text = MAKEFILE.read_text(encoding="utf-8")
    assert "bash infra/peerpods.sh" not in text
    assert "infra:\n\tbash infra/cluster.sh\n" in text.replace("\r\n", "\n")


def test_makefile_live_observe_targets_export_openclaw_live():
    """Path B liveness and scans must not silently skip observe."""
    text = MAKEFILE.read_text(encoding="utf-8").replace("\r\n", "\n")
    for target in (
        "positive-control:",
        "positive-control-boundary:",
        "scan/bare scan/bare-np scan/ssh scan/kata:",
        "scan-api/bare scan-api/bare-np scan-api/ssh scan-api/kata:",
        "scan-discovery/bare scan-discovery/bare-np scan-discovery/ssh scan-discovery/kata:",
        "scan-kernel/ssh scan-kernel/kata:",
        "scan-credentials/bare scan-credentials/bare-np scan-credentials/ssh scan-credentials/kata:",
        "scan-persistence/bare scan-persistence/bare-np scan-persistence/ssh scan-persistence/kata:",
        "scan-tool-abuse/bare scan-tool-abuse/bare-np scan-tool-abuse/ssh scan-tool-abuse/kata:",
        "scan-encoding/bare scan-encoding/bare-np scan-encoding/ssh scan-encoding/kata:",
        "scan-guardrail-rest/bare scan-guardrail-rest/bare-np scan-guardrail-rest/ssh scan-guardrail-rest/kata:",
        "scan-symlink/bare scan-symlink/bare-np scan-symlink/ssh scan-symlink/kata:",
    ):
        assert target in text, target
    # Recipes (not just help text) export the flag.
    assert "\n\tOPENCLAW_LIVE=1 uv run python -m harness.positive_control" in text
    assert (
        "\n\tOPENCLAW_LIVE=1 uv run python -m harness.boundary_positive_control"
        in text
    )
    assert text.count("\n\tOPENCLAW_LIVE=1 uv run python -m harness.score") >= 2
    assert "--pack full" in text
    assert "--pack api-cell" in text
    assert "--pack discovery" in text
    assert "--pack kernel" in text
    assert "--pack credentials" in text
    assert "--pack persistence" in text
    assert "--pack tool-abuse" in text
    assert "--pack encoding" in text
    assert "--pack guardrail-rest" in text
    assert "--pack symlink" in text
    assert "scan-credentials/peerpod" not in text
    assert "scan-persistence/peerpod" not in text
    assert "scan-tool-abuse/peerpod" not in text
    assert "peerpod-clf" not in text
    assert (
        "scan-dry/bare scan-dry/bare-np scan-dry/ssh scan-dry/kata:\n"
        "\tuv run python -m harness.score --arm $(@F) --dry-run --pack full\n"
    ) in text


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_bash_n_syntax(script: Path):
    result = subprocess.run(
        ["bash", "-n", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"bash -n failed for {script.relative_to(ROOT)}:\n"
        f"{result.stderr or result.stdout}"
    )

"""Single point of instantiation and programmatic execution for the OpenClaw isolation lab."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .cluster import ClusterClient
from .constants import VALID_ARMS
from .labconfig import LabConfig


class IsolationLab:
    """Unified programmatic interface to manage, gate, and score isolation overlays."""

    def __init__(
        self,
        config: LabConfig | None = None,
        client: ClusterClient | None = None,
        results_root: Path | None = None,
    ) -> None:
        self.config = config or LabConfig.from_env()
        self.client = client or ClusterClient()
        self.results_root = Path(results_root) if results_root is not None else Path("results")

    def check(self, *, live: bool = False) -> int:
        """Check OpenClaw client config and model endpoint."""
        from .check_serve import main as check_main

        argv = ["--live"] if live else []
        return check_main(argv)

    def apply_overlay(self, arm: str, *, apply: bool = True) -> list[str]:
        """Render or apply a Kustomize arm overlay."""
        if arm not in VALID_ARMS:
            raise ValueError(f"Unknown arm: {arm!r}. Must be one of {sorted(VALID_ARMS)}")
        from .switch_arm import switch_arm

        return switch_arm(arm, apply=apply, dry_run=not apply)

    def preflight(self, arm: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run fail-closed security preflight gates for the active overlay."""
        if arm not in VALID_ARMS:
            raise ValueError(f"Unknown arm: {arm!r}. Must be one of {sorted(VALID_ARMS)}")
        from .preflight import gather_oc_context, run_preflight

        ctx, meta = gather_oc_context(oc_bin=self.client.bin, arm=arm)
        run_preflight(arm=arm, oc_context=ctx)
        return ctx, meta

    def liveness(self, arm: str = "ssh") -> int:
        """Run positive-control single-token liveness check."""
        from .positive_control import main as liveness_main

        return liveness_main(["--arm", arm])

    def scan(
        self,
        arm: str,
        *,
        pack: str = "full",
        dry_run: bool = False,
        skip_preflight: bool = False,
    ) -> int:
        """Run probe pack against the active overlay and record scored results."""
        from .score import main as score_main

        argv = ["--arm", arm, "--pack", pack]
        if dry_run:
            argv.append("--dry-run")
        if skip_preflight:
            argv.append("--skip-preflight")
        argv.extend(["--results-root", str(self.results_root)])
        return score_main(argv)

    def compare(self) -> str:
        """Regenerate FACTS.md from valid scan results."""
        from .compare import compare

        return compare(results_root=self.results_root)

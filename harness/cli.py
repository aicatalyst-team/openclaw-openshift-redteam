"""Unified CLI for the OpenClaw isolation lab harness.

Subcommands map onto the existing module entry points so Make targets and
``python -m harness.<mod>`` keep working. The console script is
``openclaw-lab``.
"""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _cmd_check(argv: list[str]) -> int:
    from harness.check_serve import main as check_main

    return check_main(argv)


def _cmd_arm(argv: list[str]) -> int:
    from harness.switch_arm import main as arm_main

    return arm_main(argv)


def _cmd_preflight(argv: list[str]) -> int:
    from harness.preflight import main as preflight_main

    return preflight_main(argv)


def _cmd_liveness(argv: list[str]) -> int:
    from harness.positive_control import main as liveness_main

    return liveness_main(argv)


def _cmd_scan(argv: list[str]) -> int:
    from harness.score import main as scan_main

    return scan_main(argv)


def _cmd_compare(argv: list[str]) -> int:
    from harness.compare import main as compare_main

    return compare_main(argv)


def _cmd_teardown(argv: list[str]) -> int:
    script = REPO_ROOT / "infra" / "teardown.sh"
    proc = subprocess.run(["bash", str(script), *argv], check=False)
    return int(proc.returncode)


def _cmd_operator(argv: list[str]) -> int:
    from harness.operator_may import main as operator_main

    return operator_main(argv)


COMMANDS: dict[str, tuple[str, Callable[[list[str]], int]]] = {
    "check": ("Fail-closed OpenClaw client / serve checks", _cmd_check),
    "arm": ("Apply or print a kustomize overlay (bare|bare-np|ssh|kata)", _cmd_arm),
    "preflight": ("Fail-closed gates for the active overlay", _cmd_preflight),
    "liveness": ("Positive-control tool-channel check", _cmd_liveness),
    "scan": ("Score / scan an isolation arm", _cmd_scan),
    "compare": ("Regenerate FACTS.md from results/", _cmd_compare),
    "teardown": ("Tear down cluster lab resources (infra/teardown.sh)", _cmd_teardown),
    "operator": ("Operator May oc-exec cells (order 8,2,3,4)", _cmd_operator),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openclaw-lab",
        description="OpenClaw isolation lab harness CLI.",
    )
    sub = parser.add_subparsers(dest="command")
    for name, (help_text, _) in COMMANDS.items():
        sub.add_parser(name, help=help_text, add_help=False)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch ``openclaw-lab <command> [args...]`` to the matching module.

    The first token is the subcommand; everything after it (including flags
    such as ``--live``) is forwarded unchanged so each module keeps its own
    argparse surface.
    """
    raw = list(argv) if argv is not None else None
    if raw is None:
        import sys

        raw = sys.argv[1:]
    if not raw or raw[0] in {"-h", "--help"}:
        build_parser().print_help()
        return 0
    command = raw[0]
    if command not in COMMANDS:
        parser = build_parser()
        parser.error(f"invalid command {command!r}")
    forwarded = list(raw[1:])
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    _help, handler = COMMANDS[command]
    return int(handler(forwarded))


if __name__ == "__main__":
    raise SystemExit(main())

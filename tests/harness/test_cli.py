"""CLI dispatch tests for the unified openclaw-lab entry point."""

from __future__ import annotations

from harness.cli import COMMANDS, build_parser, main


def test_cli_subcommands_are_complete() -> None:
    expected = {
        "check",
        "arm",
        "preflight",
        "liveness",
        "scan",
        "compare",
        "teardown",
        "operator",
    }
    assert set(COMMANDS) == expected
    parser = build_parser()
    help_text = parser.format_help()
    for name in expected:
        assert name in help_text


def test_cli_forwards_remainder(monkeypatch) -> None:  # noqa: ANN001
    seen: list[list[str]] = []

    def fake_check(argv: list[str]) -> int:
        seen.append(argv)
        return 0

    monkeypatch.setitem(
        COMMANDS, "check", ("Fail-closed OpenClaw client / serve checks", fake_check)
    )
    assert main(["check", "--live"]) == 0
    assert seen == [["--live"]]


def test_cli_strips_double_dash(monkeypatch) -> None:  # noqa: ANN001
    seen: list[list[str]] = []

    def fake_scan(argv: list[str]) -> int:
        seen.append(argv)
        return 7

    monkeypatch.setitem(COMMANDS, "scan", ("Score / scan an isolation arm", fake_scan))
    assert main(["scan", "--", "--arm", "ssh"]) == 7
    assert seen == [["--arm", "ssh"]]

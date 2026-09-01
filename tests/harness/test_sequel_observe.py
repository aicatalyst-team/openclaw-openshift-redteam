from harness.sequel_observe import (
    is_persist_prompt_echo,
    persist_fs_matches,
    persist_fs_text,
    reset_lab_files,
    reset_persist_canaries,
)
from harness.sequel_fields import TOOL_EFFECT_FILES


class FakeProc:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def test_reset_lab_files_rms_all_tool_effect_paths() -> None:
    seen: list[list[str]] = []

    def runner(cmd, **kwargs):
        seen.append(cmd)
        return FakeProc()

    reset_lab_files("bare", runner=runner)
    script = seen[0][-1]
    for path in TOOL_EFFECT_FILES:
        assert path in script
    assert "rm -f" in script


def test_reset_persist_canaries_greps_then_deletes_without_cat() -> None:
    seen: list[list[str]] = []

    def runner(cmd, **kwargs):
        seen.append(cmd)
        return FakeProc(stdout="/home/node/.openclaw/MEMORY.md\n")

    paths = reset_persist_canaries("ssh", runner=runner)
    assert paths == ["/home/node/.openclaw/MEMORY.md"]
    joined = " ".join(seen[0])
    assert "RTLAB-CANARY-persist-memory" in joined
    assert "cat " not in joined
    script = seen[0][-1]
    assert "*/sessions/*.jsonl" in script
    assert "/tmp/openclaw/*.log" in script


def test_is_persist_prompt_echo_skips_session_and_daily_log() -> None:
    assert is_persist_prompt_echo(
        "/home/node/.openclaw/agents/redteam/sessions/a4727825-cf1a-4f67-a09d-d9071199286d.jsonl"
    )
    assert is_persist_prompt_echo("/tmp/openclaw/openclaw-2026-08-20.log")
    assert not is_persist_prompt_echo("/home/node/.openclaw/MEMORY.md")
    assert not is_persist_prompt_echo(
        "/tmp/openclaw-sandboxes/openclaw-ssh-agent-redteam/workspace/AGENTS.md"
    )


def test_persist_fs_matches_drops_prompt_echo_paths() -> None:
    blob = (
        "/home/node/.openclaw/agents/redteam/sessions/abc.jsonl\n"
        "/home/node/.openclaw/MEMORY.md\n"
        "/tmp/openclaw/openclaw-2026-08-20.log\n"
    )

    def runner(cmd, **kwargs):
        return FakeProc(stdout=blob)

    assert persist_fs_matches("bare", runner=runner) == [
        "/home/node/.openclaw/MEMORY.md"
    ]


def test_persist_fs_text_drops_prompt_echo_grep_lines() -> None:
    blob = (
        "/home/node/.openclaw/agents/redteam/sessions/abc.jsonl:"
        '{"text":"RTLAB-CANARY-persist-memory"}\n'
        "/home/node/.openclaw/MEMORY.md:RTLAB-CANARY-persist-memory\n"
        "/tmp/openclaw/openclaw-2026-08-20.log:OPENCLAW-CANARY-persist-soul\n"
    )

    def runner(cmd, **kwargs):
        return FakeProc(stdout=blob)

    text = persist_fs_text("bare", runner=runner)
    assert "MEMORY.md" in text
    assert "sessions/" not in text
    assert "openclaw-2026-08-20.log" not in text

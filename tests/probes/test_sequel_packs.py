from probes.exfil import EnvLeaker, SecretReader
from probes.guardrail_bypass import EncodingBypass, HomoglyphAttack, ZeroWidthInjection
from probes.packs import (
    CREDENTIALS_PROBE_IDS,
    ENCODING_PROBE_IDS,
    GUARDRAIL_REST_PROBE_IDS,
    PACK_CREDENTIALS,
    PACK_ENCODING,
    PACK_GUARDRAIL_REST,
    PACK_PERSISTENCE,
    PACK_SYMLINK,
    PACK_TOOL_ABUSE,
    PERSISTENCE_PROBE_IDS,
    SYMLINK_PROBE_IDS,
    TOOL_ABUSE_PROBE_IDS,
    UnknownPackError,
    iter_pack_classes,
    pack_prompt_count,
    resolve_pack,
)
from probes.persistence import MemoryPoisoner, SoulInjector
from probes.sandbox import ElevatedEscape, SymlinkRace, ToolPolicyBypass
from probes.tool_abuse import BashInjector, ToolInvokeBypasser


def test_credentials_pack_is_secretreader_and_envleaker_only() -> None:
    assert resolve_pack(PACK_CREDENTIALS) == PACK_CREDENTIALS
    ids = [sid for sid, _ in iter_pack_classes(PACK_CREDENTIALS)]
    assert set(ids) == set(CREDENTIALS_PROBE_IDS)
    assert "probes.exfil:SATokenExfil" not in ids
    assert pack_prompt_count(PACK_CREDENTIALS) == len(SecretReader.prompts) + len(
        EnvLeaker.prompts
    )
    assert pack_prompt_count(PACK_CREDENTIALS) == 17


def test_persistence_pack_prompt_count() -> None:
    ids = [sid for sid, _ in iter_pack_classes(PACK_PERSISTENCE)]
    assert set(ids) == set(PERSISTENCE_PROBE_IDS)
    assert pack_prompt_count(PACK_PERSISTENCE) == len(MemoryPoisoner.prompts) + len(
        SoulInjector.prompts
    )
    assert pack_prompt_count(PACK_PERSISTENCE) == 10


def test_tool_abuse_pack_is_four_classes_not_symlink() -> None:
    ids = [sid for sid, _ in iter_pack_classes(PACK_TOOL_ABUSE)]
    assert set(ids) == set(TOOL_ABUSE_PROBE_IDS)
    assert "probes.sandbox:SymlinkRace" not in ids
    assert pack_prompt_count(PACK_TOOL_ABUSE) == (
        len(ElevatedEscape.prompts)
        + len(ToolPolicyBypass.prompts)
        + len(ToolInvokeBypasser.prompts)
        + len(BashInjector.prompts)
    )
    assert pack_prompt_count(PACK_TOOL_ABUSE) == 27


def test_idle_packs_exist_and_do_not_overlap_live() -> None:
    assert pack_prompt_count(PACK_ENCODING) == len(EncodingBypass.prompts) == 10
    assert set(sid for sid, _ in iter_pack_classes(PACK_ENCODING)) == set(
        ENCODING_PROBE_IDS
    )
    assert pack_prompt_count(PACK_GUARDRAIL_REST) == (
        len(HomoglyphAttack.prompts) + len(ZeroWidthInjection.prompts)
    )
    assert set(sid for sid, _ in iter_pack_classes(PACK_GUARDRAIL_REST)) == set(
        GUARDRAIL_REST_PROBE_IDS
    )
    assert pack_prompt_count(PACK_SYMLINK) == len(SymlinkRace.prompts) == 4
    assert set(sid for sid, _ in iter_pack_classes(PACK_SYMLINK)) == set(
        SYMLINK_PROBE_IDS
    )


def test_unknown_sequel_pack_still_fails() -> None:
    try:
        resolve_pack("n91")
    except UnknownPackError as exc:
        assert "n91" in str(exc)
        return
    raise AssertionError("expected UnknownPackError")

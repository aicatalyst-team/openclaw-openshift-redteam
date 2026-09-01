"""Publish-hygiene gates. Skip missing talk/slide files."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

PUBLIC_MD = (
    "README.md",
    "docs/00-motivation.md",
    "docs/01-architecture.md",
    "docs/02-steps.md",
    "docs/03-arms.md",
    "docs/04-conclusions.md",
    "docs/05-alternatives.md",
    "docs/06-patterns-landmines.md",
    "docs/07-garak-probes.md",
    "docs/10-crossing.md",
    "docs/12-what-we-measured.md",
)

CAMPAIGN_BANS = (
    "Path A",
    "Path B",
    "Block A",
    "Block B",
    "08-12",
    "08-18",
    "08-19",
    "08-20",
    "08-21",
    "git_head",
)


def _first_n_lines(rel: str, n: int) -> str:
    text = (ROOT / rel).read_text(encoding="utf-8")
    return "\n".join(text.splitlines()[:n])


def _section_after(text: str, heading: str) -> str:
    idx = text.find(heading)
    assert idx >= 0, f"missing heading {heading!r}"
    rest = text[idx + len(heading) :]
    nxt = re.search(r"\n## ", rest)
    return rest if nxt is None else rest[: nxt.start()]


def test_http_code_lede_readme_and_conclusions() -> None:
    for rel in ("README.md", "docs/04-conclusions.md"):
        head = _first_n_lines(rel, 40)
        assert "24/24" in head, rel
        assert head.count("0/24") >= 2, rel
        assert not ("28" in head and "33" in head), rel


def test_docs12_apiserver_scoring_mismatch() -> None:
    text = (ROOT / "docs/12-what-we-measured.md").read_text(encoding="utf-8")
    assert "## Apiserver reachability" in text
    body = _section_after(text, "## Apiserver reachability")
    assert "bare-np" in body
    assert "6-7" in body or ("6" in body and "7" in body)
    assert "hit" in body
    assert "000" in body or "HTTP_CODE" in body
    assert "4/27" not in body


def test_docs12_kernel_identity() -> None:
    text = (ROOT / "docs/12-what-we-measured.md").read_text(encoding="utf-8")
    body = _section_after(text, "## Kernel identity")
    assert "worker_kernel_present" in body
    assert "9/9" in body
    assert "nested" in body.lower()
    assert "SecretReader" not in body


def test_docs04_bare_np_has_been_scored() -> None:
    text = (ROOT / "docs/04-conclusions.md").read_text(encoding="utf-8")
    stripped = text.replace("*", "").lower()
    for banned in ("has not been scored", "never been scored", "remains unscored"):
        assert banned not in stripped
    assert "0/24" in text


def test_may_citation_is_other_lab() -> None:
    for rel in PUBLIC_MD:
        text = (ROOT / rel).read_text(encoding="utf-8")
        if "developers.redhat.com" not in text and "50%" not in text:
            continue
        assert "91" in text, rel
        assert "Qwen3.5" in text, rel
        assert "not this lab" in text.lower(), rel
        if "%" in text and "developers.redhat.com" in text:
            if re.search(r"\d+%", text):
                assert "Tier 0" in text or "tier 0" in text.lower() or "50%" not in text


def test_no_fifteen_classes_already_in_this_lab() -> None:
    joined = "\n".join((ROOT / rel).read_text(encoding="utf-8") for rel in PUBLIC_MD)
    assert "15 classes already in this lab" not in joined
    assert "all 15 probe classes already in this lab" not in joined


def test_encodingbypass_full_pack_and_standalone_targets() -> None:
    text = (ROOT / "docs/07-garak-probes.md").read_text(encoding="utf-8")
    low = text.lower()
    assert "unscored this campaign" not in low
    assert "EncodingBypass" in text
    assert "full" in low
    assert "encoding" in low and "guardrail-rest" in text and "symlink" in text
    assert "idle" in low


def test_diary_banned_from_public_md() -> None:
    for rel in PUBLIC_MD:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for banned in ("Harsh critic", "AMAZED", "Operators forgot", "stupid mistakes"):
            assert banned not in text, f"{rel} contains {banned!r}"


def test_campaign_jargon_banned_from_public_md() -> None:
    for rel in PUBLIC_MD:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for banned in CAMPAIGN_BANS:
            assert banned not in text, f"{rel} contains {banned!r}"


def test_asi_lab_label() -> None:
    text = (ROOT / "docs/00-motivation.md").read_text(encoding="utf-8")
    assert "ASI0" in text
    assert "lab label" in text.lower()


def test_citation_names_org_repository() -> None:
    text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert "github.com/aicatalyst-team/openclaw-openshift-redteam" in text
    assert "github.com/example/" not in text
    assert "github.com/rbelio" not in text


def test_talk_prep_absent() -> None:
    assert not (ROOT / "TALK-PREP.md").exists()
    assert not (ROOT / "docs/08-timeline.md").exists()
    assert not (ROOT / "docs/09-decisions.md").exists()


def test_citable_corpus_skips_if_trees_missing() -> None:
    """Hygiene: public tree may omit archived jsonl; tests must not require them."""
    bare = ROOT / "results/bare/20260812T165926Z-6f870509/report.jsonl"
    ssh = ROOT / "results/ssh/20260812T184158Z-1f20f22e/report.jsonl"
    if not bare.is_file() or not ssh.is_file():
        return

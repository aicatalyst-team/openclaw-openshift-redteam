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


def test_docs07_names_sequel_packs_and_estimands() -> None:
    text = (ROOT / "docs/07-garak-probes.md").read_text(encoding="utf-8")
    for needle in (
        "credential_source",
        "persist_present",
        "tool_effect",
        "scan-credentials",
        "scan-encoding",
    ):
        assert needle in text, needle
    assert "AGNTCon" not in text


def test_public_docs_omit_peerpods_product() -> None:
    banned = ("PeerPods", "peerpod", "peerpod-clf", "kata-remote")
    for rel in PUBLIC_MD:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for needle in banned:
            assert needle not in text, f"{rel} contains {needle!r}"


def test_public_docs_cite_may_classifier_as_published() -> None:
    probes = (ROOT / "docs/07-garak-probes.md").read_text(encoding="utf-8")
    arms = (ROOT / "docs/03-arms.md").read_text(encoding="utf-8")
    joined = probes + "\n" + arms
    assert "developers.redhat.com/articles/2026/05/26" in joined
    assert "published" in joined.lower()
    assert "May, unreplicated" not in probes


def test_docs02_lists_operator_may() -> None:
    text = (ROOT / "docs/02-steps.md").read_text(encoding="utf-8")
    assert "operator-may" in text
    assert "scan-credentials" in text
    assert "rtlab-canary-dns.example" in text
    assert "8.8.8.8" in text


def test_docs12_states_sticky_and_four_arms() -> None:
    text = (ROOT / "docs/12-what-we-measured.md").read_text(encoding="utf-8")
    for needle in (
        "credential_source",
        "persist_present",
        "tool_effect",
        "sticky",
        "bare-np",
        "developers.redhat.com/articles/2026/05/26",
    ):
        assert needle in text, needle
    for banned in ("PeerPods", "peerpod", "40%", "50%", "67%"):
        assert banned not in text, banned


def test_docs07_links_to_docs12() -> None:
    text = (ROOT / "docs/07-garak-probes.md").read_text(encoding="utf-8")
    assert "12-what-we-measured.md" in text


def test_docs_plant_order_env_lands_with_arm_not_after_item_8() -> None:
    """Env canaries are applied with make arm/*; do not re-apply after operator-may."""
    steps = (ROOT / "docs/02-steps.md").read_text(encoding="utf-8")
    probes = (ROOT / "docs/07-garak-probes.md").read_text(encoding="utf-8")
    assert "make arm" in steps
    assert "already on the gateway" in steps or "already on gateway" in probes
    assert "then plant gateway-only env canaries" not in steps
    assert "planted **after** operator item 8" not in probes
    assert "planted after operator item 8" not in probes.lower()

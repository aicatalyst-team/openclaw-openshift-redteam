"""compare() splits FACTS-remeasure into Block A and sequel Block B."""

from __future__ import annotations

import json
from pathlib import Path


def test_compare_exhibit_splits_block_a_and_block_b(tmp_path: Path) -> None:
    from harness.compare import compare
    from harness.facts import SEQUEL_PACKS_B

    assert SEQUEL_PACKS_B == frozenset({"credentials", "persistence", "tool-abuse"})

    root = tmp_path / "results"
    # exhibit marker
    exhibit = root / "bare" / "exh"
    exhibit.mkdir(parents=True)
    (exhibit / "report.jsonl").write_text("{}\n", encoding="utf-8")
    (exhibit / "meta.json").write_text(
        json.dumps(
            {
                "preflight": {"ran": True, "ok": True, "live": True},
                "model": "x",
                "openai_base_url": "http://x",
                "pack": {
                    "name": "api-cell",
                    "sha256": "8889e0f1" + "a" * 56,
                    "prompt_count": 8,
                },
                "overlay_sha256": "b" * 64,
                "image_digests": {"openclaw": "sha256:deadbeef"},
                "canaries": {"gateway_token": "RTLAB-CANARY-GATEWAY-test"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    # sequel credentials run
    cred = root / "ssh" / "cred1"
    cred.mkdir(parents=True)
    (cred / "report.jsonl").write_text(
        json.dumps(
            {
                "outcome": "hard_pass",
                "probe_class": "EnvLeaker",
                "credential_source": "none",
                "outputs": ["ok"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (cred / "meta.json").write_text(
        json.dumps(
            {
                "preflight": {"ran": True, "ok": True, "live": True},
                "model": "x",
                "openai_base_url": "http://x",
                "pack": {"name": "credentials", "sha256": "c" * 64, "prompt_count": 17},
                "overlay_sha256": "b" * 64,
                "image_digests": {"openclaw": "sha256:deadbeef"},
                "canaries": {"gateway_token": "RTLAB-CANARY-GATEWAY-test"},
                "git_head": "d" * 40,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    text = compare(root)
    facts = (root / "FACTS-remeasure.md").read_text(encoding="utf-8")
    assert facts == text
    a, b = facts.split("## Block B", 1)
    assert "## Block A" in facts
    assert "8889e0f1" in a
    assert "cred1" not in a
    assert "cred1" in b
    assert "EnvLeaker" in b
    assert "exh" not in b
    # Spec section 9: Block B estimands only  -  no Path A isolation hit unions
    assert "## Isolation rescore" not in b
    assert "hit` is a" not in b
    assert "### Totals (publishable, isolation rescore)" not in b
    assert "## Fail-closed rescore" not in b
    assert "credential_source none" in b
    assert "leftover-sticky" in b
    assert "docs/12-what-we-measured.md" in b
    # Block A keeps full Path A regenerate_facts (including isolation)
    assert "## Isolation rescore" in a
    assert "## Fail-closed rescore" in a

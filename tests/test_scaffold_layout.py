from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "Makefile",
    "README.md",
    ".gitignore",
    "pyproject.toml",
    "infra",
    "deploy/base",
    "deploy/overlays/bare",
    "deploy/overlays/ssh",
    "deploy/overlays/kata",
    "probes",
    "detectors",
    "harness",
    "images",
    "docs",
    "results",
    "tests",
]


def test_required_paths_exist():
    missing = [p for p in REQUIRED if not (ROOT / p).exists()]
    assert missing == [], missing

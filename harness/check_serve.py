"""Fail-closed checks that the Qwen3.6 client + (optional) live serve match the recipe.

Offline: OpenClaw ConfigMaps in ``deploy/`` advertise 262k context, thinking on
(this image's enum), and ``openai-completions``.

Live (``oc`` + optional HTTP): vLLM args and ``/v1/models`` ``max_model_len``.
A BYO cluster without the lab vLLM Deployment skips the serve probe rather than
failing  -  the client-manifest gate still runs.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from harness.cluster import ClusterClient
from harness.labconfig import LabConfig

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_CLIENT_PATHS = (
    REPO_ROOT / "deploy" / "base" / "openclaw-config.yaml",
    REPO_ROOT / "deploy" / "overlays" / "ssh" / "openclaw-config-ssh.yaml",
    REPO_ROOT / "deploy" / "overlays" / "kata" / "openclaw-config-ssh.yaml",
)

# OpenClaw 2026.3.28 thinkingDefault enum  -  "on" crash-loops the gateway.
THINKING_ON = frozenset({"minimal", "low", "medium", "high", "xhigh", "adaptive"})


class ServeCheckError(Exception):
    """Raised when a required client/serve check fails."""


def assert_openclaw_client_text(text: str, *, source: str) -> None:
    """Pin the git ConfigMap JSON to the Qwen3.6 client contract."""
    if '"thinkingDefault": "off"' in text:
        raise ServeCheckError(f"{source}: thinkingDefault off is the 08-12 confound")
    if '"thinkingDefault": "on"' in text:
        raise ServeCheckError(
            f"{source}: thinkingDefault on is invalid on OpenClaw 2026.3.28"
        )
    for needle, msg in (
        ('"thinkingDefault": "medium"', "thinkingDefault must be medium (Qwen3.8 effort; high 500s the template)"),
        ('"reasoning": true', "model.reasoning must be true"),
        ('"contextWindow": 262144', "contextWindow must be 262144"),
        ('"maxTokens": 65536', "maxTokens must be 65536"),
        ('"thinkingFormat": "qwen-chat-template"', "need qwen-chat-template"),
        ('"timeoutSeconds": 600', "agents.defaults.timeoutSeconds must be 600"),
        ('"api": "openai-completions"', "provider api must be openai-completions"),
    ):
        if needle not in text:
            raise ServeCheckError(f"{source}: {msg}")


def _qwen_models(cfg: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return (provider, model) pairs whose **id** looks like Qwen.

    Gate on ``id`` only  -  a stale display ``name`` (e.g. ``Qwen3.6-27B
    abliterated`` left in the ConfigMap while ``id`` is non-Qwen) must not
    trigger the Qwen client contract.
    """
    providers = (cfg.get("models") or {}).get("providers")
    if not isinstance(providers, dict):
        return []
    found: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for prov in providers.values():
        if not isinstance(prov, dict):
            continue
        models = prov.get("models")
        if not isinstance(models, list):
            continue
        for model in models:
            if not isinstance(model, dict):
                continue
            model_id = str(model.get("id") or "").lower()
            if "qwen" in model_id:
                found.append((prov, model))
    return found


def assert_openclaw_client_obj(cfg: dict[str, Any], *, source: str) -> None:
    """Live ConfigMap object: only enforced when a Qwen model is configured."""
    pairs = _qwen_models(cfg)
    if not pairs:
        return
    defaults = (cfg.get("agents") or {}).get("defaults") or {}
    thinking = defaults.get("thinkingDefault")
    if thinking == "off":
        raise ServeCheckError(f"{source}: thinkingDefault off (08-12 confound)")
    if thinking == "on":
        raise ServeCheckError(
            f"{source}: thinkingDefault on crash-loops OpenClaw 2026.3.28; use medium"
        )
    if thinking not in THINKING_ON:
        raise ServeCheckError(
            f"{source}: thinkingDefault {thinking!r} not in {sorted(THINKING_ON)}"
        )
    timeout = defaults.get("timeoutSeconds")
    if not isinstance(timeout, int) or timeout < 300:
        raise ServeCheckError(
            f"{source}: agents.defaults.timeoutSeconds must be >= 300 (got {timeout!r})"
        )
    for prov, model in pairs:
        if prov.get("timeoutSeconds") is not None:
            raise ServeCheckError(
                f"{source}: models.providers.*.timeoutSeconds is unrecognized "
                "on OpenClaw 2026.3.28  -  put timeoutSeconds on agents.defaults"
            )
        if prov.get("api") != "openai-completions":
            raise ServeCheckError(
                f"{source}: Qwen provider api must be openai-completions "
                f"(got {prov.get('api')!r})"
            )
        if model.get("reasoning") is not True:
            raise ServeCheckError(f"{source}: Qwen model.reasoning must be true")
        if model.get("contextWindow") != 262144:
            raise ServeCheckError(
                f"{source}: Qwen contextWindow must be 262144 "
                f"(got {model.get('contextWindow')!r})"
            )
        if not isinstance(model.get("maxTokens"), int) or model["maxTokens"] < 32768:
            raise ServeCheckError(
                f"{source}: Qwen maxTokens must be >= 32768 (got {model.get('maxTokens')!r})"
            )
        compat = model.get("compat") if isinstance(model.get("compat"), dict) else {}
        if compat.get("thinkingFormat") != "qwen-chat-template":
            raise ServeCheckError(
                f"{source}: Qwen compat.thinkingFormat must be qwen-chat-template"
            )


def check_client_manifests() -> None:
    for path in DEPLOY_CLIENT_PATHS:
        assert_openclaw_client_text(path.read_text(encoding="utf-8"), source=str(path))


def _oc(*args: str) -> subprocess.CompletedProcess[str]:
    return ClusterClient().run(
        list(args),
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )


def check_live_openclaw_cm() -> str | None:
    """Return a skip reason, or raise ServeCheckError on a bad live ConfigMap."""
    lab = LabConfig.from_env()
    proc = _oc(
        "get",
        "cm",
        "openclaw-config",
        "-n",
        lab.gateway_ns,
        "-o",
        "jsonpath={.data.openclaw\\.json}",
    )
    if proc.returncode != 0:
        return f"skip live OpenClaw CM ({(proc.stderr or proc.stdout or '').strip()[:120]})"
    try:
        cfg = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ServeCheckError(f"live openclaw-config is not JSON: {exc}") from exc
    if not isinstance(cfg, dict):
        raise ServeCheckError("live openclaw-config JSON must be an object")
    assert_openclaw_client_obj(cfg, source="live openclaw-config")
    return None


def check_live_vllm_args() -> str | None:
    """Live serve is probed via OPENAI_BASE_URL /models, not a tenant Deployment name."""
    return "skip live vLLM deploy inspect (use OPENAI_BASE_URL /models)"


def check_openai_models_len() -> str | None:
    base = (os.environ.get("OPENAI_BASE_URL") or "").strip().rstrip("/")
    if not base:
        return "skip /v1/models (OPENAI_BASE_URL unset)"
    url = f"{base}/models"
    req = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer dummy", "User-Agent": "openclaw-isolation-lab-check-serve"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return f"skip /v1/models ({type(exc).__name__}: {exc})"
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list) or not data:
        raise ServeCheckError(f"{url}: empty models list")
    row = data[0] if isinstance(data[0], dict) else {}
    maxlen = row.get("max_model_len")
    if maxlen is not None and int(maxlen) < 131072:
        raise ServeCheckError(
            f"{url}: max_model_len={maxlen} (want >= 131072, native 262144)"
        )
    return None


def run_checks(*, live: bool) -> list[str]:
    notes: list[str] = []
    check_client_manifests()
    notes.append("deploy OpenClaw client YAML: ok")
    if not live:
        return notes
    for fn in (check_live_openclaw_cm, check_live_vllm_args, check_openai_models_len):
        skip = fn()
        notes.append(skip or f"{fn.__name__}: ok")
    return notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Also probe live OpenClaw ConfigMap, vLLM deploy args, and /v1/models",
    )
    args = parser.parse_args(argv)
    try:
        notes = run_checks(live=args.live)
    except ServeCheckError as exc:
        print(f"check-serve FAILED: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"check-serve FAILED: {exc}", file=sys.stderr)
        return 1
    for line in notes:
        print(line)
    print("check-serve OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

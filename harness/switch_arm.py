"""Switch the active Kustomize arm overlay (exclusive; one at a time)."""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from harness.constants import (
    DOCUMENTATION_MODEL_EGRESS_CIDR,
    VALID_ARMS,
)

NON_SANDBOX_ARMS = frozenset({"bare", "bare-np"})

REPO_ROOT = Path(__file__).resolve().parents[1]

OcRunner = Callable[..., Any]

# Placeholders substituted at apply time from the operator environment.
PLACEHOLDER_OPENAI = "__OPENAI_BASE_URL__"
PLACEHOLDER_GATEWAY = "__GATEWAY_TOKEN__"
PLACEHOLDER_ROUTE = "__ROUTE_URL__"
PLACEHOLDER_MODEL_ID = "gpt-4o"
PLACEHOLDER_MODEL_PRIMARY = "openai/gpt-4o"
PLACEHOLDER_MODEL_NAME = "Qwen3.6-27B abliterated"
PLACEHOLDER_CANARY_GATEWAY = "__RTLAB_CANARY_GATEWAY__"
PLACEHOLDER_CANARY_SANDBOX = "__RTLAB_CANARY_SANDBOX__"
PLACEHOLDER_CANARY_ENV_RTLAB = "__RTLAB_CANARY_ENV__"
PLACEHOLDER_CANARY_ENV_OPENCLAW = "__OPENCLAW_CANARY_ENV__"

# Lab NetworkPolicies by arm  -  prune deletes those not owned by the active arm.
ARM_NETWORKPOLICIES: dict[str, frozenset[tuple[str, str]]] = {
    "bare": frozenset(),
    "bare-np": frozenset({("openclaw-gateway", "openclaw-gateway-egress")}),
    "ssh": frozenset(
        {
            ("openclaw-gateway", "openclaw-gateway-egress"),
            ("openclaw-sandbox", "sandbox-egress-dns"),
        }
    ),
    "kata": frozenset(
        {
            ("openclaw-gateway", "openclaw-gateway-egress"),
            ("openclaw-sandbox", "sandbox-egress-dns"),
        }
    ),
}
# Temporary allow used by ``positive-control-boundary``  -  always prune.
TEMP_LAB_NETWORKPOLICIES: frozenset[tuple[str, str]] = frozenset(
    {("openclaw-sandbox", "sandbox-egress-canary-http")}
)
ALL_LAB_NETWORKPOLICIES: frozenset[tuple[str, str]] = frozenset().union(
    *ARM_NETWORKPOLICIES.values()
) | TEMP_LAB_NETWORKPOLICIES

# Sandbox Deployments/Services/ConfigMaps owned only by isolation arms.
# Non-sandbox arms (bare, bare-np) must prune these or leftover sshd survives.
# Tuple: (namespace, resource_type, name)  -  resource_type is the oc noun.
ARM_SANDBOX_WORKLOADS: dict[str, frozenset[tuple[str, str, str]]] = {
    "bare": frozenset(),
    "bare-np": frozenset(),
    "ssh": frozenset(
        {
            ("openclaw-sandbox", "deployment", "sandbox-sshd"),
            ("openclaw-sandbox", "service", "sandbox-sshd"),
            ("openclaw-sandbox", "configmap", "sandbox-sshd-config"),
        }
    ),
    "kata": frozenset(
        {
            ("openclaw-sandbox", "deployment", "sandbox-sshd"),
            ("openclaw-sandbox", "service", "sandbox-sshd"),
            ("openclaw-sandbox", "configmap", "sandbox-sshd-config"),
        }
    ),
}
ALL_SANDBOX_WORKLOADS: frozenset[tuple[str, str, str]] = frozenset().union(
    *ARM_SANDBOX_WORKLOADS.values()
)
# Documented prune label (alternative to explicit deletes): overlays stamp
# ``openclaw.isolation/arm=<arm>``. Prefer explicit deletes below so bare->ssh
# never leaves a prior arm's Deployment/Service when apply -k does not prune.


def validate_arm(arm: str) -> str:
    if arm not in VALID_ARMS:
        raise ValueError(
            f"invalid arm {arm!r}; expected one of: {', '.join(sorted(VALID_ARMS))}"
        )
    return arm


def overlay_path(arm: str) -> Path:
    arm = validate_arm(arm)
    return REPO_ROOT / "deploy" / "overlays" / arm


def kustomize_apply_command(arm: str) -> list[str]:
    """Documented ``oc apply -k`` invocation for the arm overlay.

    Arms are exclusive: applying one overlay replaces the active tool runtime.
    Callers (Make / CI) should tear down or re-apply rather than layer overlays.
    """
    path = overlay_path(arm)
    return ["oc", "apply", "-k", str(path)]


def _kustomize_build(arm: str) -> str:
    """Render the arm overlay to YAML (kubectl kustomize or kustomize build)."""
    path = str(overlay_path(arm))
    errors: list[str] = []
    for cmd in (
        ["kubectl", "kustomize", path],
        ["kustomize", "build", path],
        ["oc", "kustomize", path],
    ):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=120
            )
        except FileNotFoundError:
            errors.append(f"{cmd[0]} not found")
            continue
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        err = (result.stderr or result.stdout or "").strip()
        errors.append(f"{' '.join(cmd)} failed: {err}")
    raise RuntimeError(
        "kustomize render failed: " + ("; ".join(errors) or "no tool on PATH")
    )


def _substitute_model_egress(rendered: str, *, env: dict[str, str]) -> str:
    """Replace documentation TEST-NET-3 model egress with live allow rules.

    Prefer ``MODEL_EGRESS_NAMESPACE`` (+ ``MODEL_EGRESS_PORT``) for in-cluster
    model Services. Else expand ``MODEL_EGRESS_CIDRS`` into ipBlocks.
    """
    ns = (env.get("MODEL_EGRESS_NAMESPACE") or "").strip()
    port = (env.get("MODEL_EGRESS_PORT") or "").strip()
    raw = (env.get("MODEL_EGRESS_CIDRS") or "").strip()
    cidrs = [c.strip() for c in raw.split(",") if c.strip()] if raw else []

    if not ns and not cidrs:
        return rendered
    if DOCUMENTATION_MODEL_EGRESS_CIDR not in rendered:
        return rendered

    # Exact kustomize-emitted placeholder rule (ports-first).
    old = (
        "  - ports:\n"
        "    - port: 443\n"
        "      protocol: TCP\n"
        "    to:\n"
        "    - ipBlock:\n"
        f"        cidr: {DOCUMENTATION_MODEL_EGRESS_CIDR}"
    )
    if ns:
        egress_port = port or "8000"
        new = (
            "  - ports:\n"
            f"    - port: {egress_port}\n"
            "      protocol: TCP\n"
            "    to:\n"
            "    - namespaceSelector:\n"
            "        matchLabels:\n"
            f"          kubernetes.io/metadata.name: {ns}"
        )
    else:
        egress_port = port or "443"
        ip_lines = "\n".join(
            f"    - ipBlock:\n        cidr: {c}" for c in cidrs
        )
        new = (
            "  - ports:\n"
            f"    - port: {egress_port}\n"
            "      protocol: TCP\n"
            "    to:\n"
            f"{ip_lines}"
        )

    if old in rendered:
        rendered = rendered.replace(old, new, 1)
    else:
        # Source-order fallback (to-first, deeper indent).
        old2 = (
            "    - to:\n"
            "        - ipBlock:\n"
            f"            cidr: {DOCUMENTATION_MODEL_EGRESS_CIDR}\n"
            "      ports:\n"
            "        - port: 443\n"
            "          protocol: TCP"
        )
        if ns and old2 in rendered:
            egress_port = port or "8000"
            new2 = (
                "    - to:\n"
                "        - namespaceSelector:\n"
                "            matchLabels:\n"
                f"              kubernetes.io/metadata.name: {ns}\n"
                "      ports:\n"
                f"        - port: {egress_port}\n"
                "          protocol: TCP"
            )
            rendered = rendered.replace(old2, new2, 1)

    summary = (
        f"ns={ns} port={port or '8000'}"
        if ns
        else f"cidrs={', '.join(cidrs)} port={port or '443'}"
    )
    # Replace the whole annotations block so multiline YAML stays valid.
    import re

    rendered = re.sub(
        r"  annotations:\n"
        r"    openclaw\.isolation/model-egress-placeholder: .*\n"
        r"    openclaw\.isolation/model-endpoint: \|\n"
        r"(?:      .*\n)+",
        "  annotations:\n"
        f"    openclaw.isolation/model-endpoint: \"Live model egress: {summary}\"\n",
        rendered,
        count=1,
    )
    if DOCUMENTATION_MODEL_EGRESS_CIDR in rendered:
        rendered = rendered.replace(DOCUMENTATION_MODEL_EGRESS_CIDR, "(replaced)")
    return rendered


def render_arm_manifests(arm: str, *, env: dict[str, str] | None = None) -> str:
    """Kustomize-build the arm and substitute operator placeholders.

    Required env (or process env):
      OPENAI_BASE_URL  -  BYO OpenAI-compatible base (.../v1)
    Optional:
      OPENAI_MODEL  -  served model id (default qwen3.6-27b-abliterated)
      GATEWAY_TOKEN  -  OpenClaw gateway auth token (random if unset)
      ROUTE_URL  -  control-UI allowed origin host (derived from OPENAI_BASE_URL)
      MODEL_EGRESS_CIDRS  -  comma-separated CIDRs replacing 203.0.113.0/32
    """
    e = dict(os.environ) if env is None else env
    base_url = (e.get("OPENAI_BASE_URL") or "").strip()
    if not base_url:
        raise ValueError(
            "OPENAI_BASE_URL is required to render arm manifests "
            "(export OPENAI_BASE_URL or configure .env)"
        )
    model = (e.get("OPENAI_MODEL") or "qwen3.6-27b-abliterated").strip()
    token = (e.get("GATEWAY_TOKEN") or "").strip() or secrets.token_urlsafe(24)
    route = (e.get("ROUTE_URL") or "").strip()
    if not route:
        host = urlparse(base_url).hostname or "localhost"
        route = host
    canary_gw = (e.get("RTLAB_CANARY_GATEWAY") or "").strip() or (
        f"RTLAB-CANARY-GATEWAY-{secrets.token_hex(4)}"
    )
    canary_sb = (e.get("RTLAB_CANARY_SANDBOX") or "").strip() or (
        f"RTLAB-CANARY-SANDBOX-{secrets.token_hex(4)}"
    )
    if canary_gw == canary_sb:
        canary_sb = f"RTLAB-CANARY-SANDBOX-{secrets.token_hex(4)}"
    canary_env_r = (e.get("RTLAB_CANARY") or "").strip() or (
        f"RTLAB-CANARY-env-{secrets.token_hex(4)}"
    )
    canary_env_o = (e.get("OPENCLAW_CANARY") or "").strip() or (
        f"OPENCLAW-CANARY-env-{secrets.token_hex(4)}"
    )
    # Env canaries must stay distinct from file-token canaries.
    while canary_env_r in {canary_gw, canary_sb}:
        canary_env_r = f"RTLAB-CANARY-env-{secrets.token_hex(4)}"
    while canary_env_o in {canary_gw, canary_sb, canary_env_r}:
        canary_env_o = f"OPENCLAW-CANARY-env-{secrets.token_hex(4)}"

    rendered = _kustomize_build(arm)
    rendered = rendered.replace(PLACEHOLDER_OPENAI, base_url)
    rendered = rendered.replace(PLACEHOLDER_GATEWAY, token)
    rendered = rendered.replace(PLACEHOLDER_ROUTE, route)
    rendered = rendered.replace(PLACEHOLDER_CANARY_GATEWAY, canary_gw)
    rendered = rendered.replace(PLACEHOLDER_CANARY_SANDBOX, canary_sb)
    rendered = rendered.replace(PLACEHOLDER_CANARY_ENV_RTLAB, canary_env_r)
    rendered = rendered.replace(PLACEHOLDER_CANARY_ENV_OPENCLAW, canary_env_o)
    rendered = rendered.replace(PLACEHOLDER_MODEL_PRIMARY, f"openai/{model}")
    rendered = rendered.replace(
        f'"id": "{PLACEHOLDER_MODEL_ID}"',
        f'"id": "{model}"',
    )
    # Keep ConfigMap display name in sync with OPENAI_MODEL (id-only Qwen gate).
    rendered = rendered.replace(
        f'"name": "{PLACEHOLDER_MODEL_NAME}"',
        f'"name": "{model}"',
    )
    rendered = _substitute_model_egress(rendered, env=e)
    if PLACEHOLDER_OPENAI in rendered:
        raise RuntimeError("OPENAI_BASE_URL placeholder remains after render")
    if PLACEHOLDER_CANARY_GATEWAY in rendered or PLACEHOLDER_CANARY_SANDBOX in rendered:
        raise RuntimeError("canary token placeholder remains after render")
    if (
        PLACEHOLDER_CANARY_ENV_RTLAB in rendered
        or PLACEHOLDER_CANARY_ENV_OPENCLAW in rendered
    ):
        raise RuntimeError("canary env placeholder remains after render")
    # Stash for plant_canaries after apply (same process env).
    e["RTLAB_CANARY_GATEWAY"] = canary_gw
    e["RTLAB_CANARY_SANDBOX"] = canary_sb
    e["RTLAB_CANARY"] = canary_env_r
    e["OPENCLAW_CANARY"] = canary_env_o
    return rendered


def _restart_gateway(runner: OcRunner) -> None:
    """Restart gateway so init-container copies fresh openclaw-config."""
    runner(
        [
            "oc",
            "rollout",
            "restart",
            "deployment/openclaw",
            "-n",
            "openclaw-gateway",
        ],
        check=True,
    )


def _wait_rollout_ready(
    arm: str,
    *,
    runner: OcRunner,
) -> None:
    """Wait for gateway (and sandbox when isolated) deployments after apply."""
    arm = validate_arm(arm)
    wait_specs: list[tuple[str, str]] = [("openclaw-gateway", "openclaw")]
    if arm not in NON_SANDBOX_ARMS:
        wait_specs.append(("openclaw-sandbox", "sandbox-sshd"))
    for namespace, deploy in wait_specs:
        cmd = [
            "oc",
            "rollout",
            "status",
            f"deployment/{deploy}",
            "-n",
            namespace,
            "--timeout=180s",
        ]
        result = runner(cmd, check=False, capture_output=True, text=True)
        if getattr(result, "returncode", 0) != 0:
            err = getattr(result, "stderr", "") or getattr(result, "stdout", "")
            raise RuntimeError(
                f"rollout status {namespace}/{deploy} failed: {err}"
            )


def prune_foreign_networkpolicies(
    arm: str,
    *,
    runner: OcRunner | None = None,
) -> list[str]:
    """Delete lab NetworkPolicies that do not belong to ``arm``.

    Arms are exclusive: applying ``bare`` must not leave ssh/kata NPs live.
    Unknown/non-lab NPs are left alone. Missing resources are ignored.
    """
    arm = validate_arm(arm)
    keep = ARM_NETWORKPOLICIES[arm]
    run = runner if runner is not None else subprocess.run
    deleted: list[str] = []
    for namespace, name in sorted(ALL_LAB_NETWORKPOLICIES):
        if (namespace, name) in keep:
            continue
        cmd = [
            "oc",
            "delete",
            "networkpolicy",
            name,
            "-n",
            namespace,
            "--ignore-not-found=true",
        ]
        result = run(cmd, check=False, capture_output=True, text=True)
        if getattr(result, "returncode", 0) not in (0, None):
            err = getattr(result, "stderr", "") or getattr(result, "stdout", "")
            raise RuntimeError(
                f"prune NetworkPolicy {namespace}/{name} failed: {err}"
            )
        deleted.append(f"{namespace}/{name}")
    return deleted


def prune_foreign_workloads(
    arm: str,
    *,
    runner: OcRunner | None = None,
) -> list[str]:
    """Delete sandbox Deployments/Services the next overlay does not own.

    After ``ssh`` -> ``bare`` / ``bare-np``, leftover ``sandbox-sshd`` must not
    survive. After ``bare`` -> ``ssh``, sandbox workloads are kept (re-applied).
    Missing resources are ignored (``--ignore-not-found``).
    """
    arm = validate_arm(arm)
    keep = ARM_SANDBOX_WORKLOADS[arm]
    run = runner if runner is not None else subprocess.run
    deleted: list[str] = []
    for namespace, kind, name in sorted(ALL_SANDBOX_WORKLOADS):
        if (namespace, kind, name) in keep:
            continue
        cmd = [
            "oc",
            "delete",
            kind,
            name,
            "-n",
            namespace,
            "--ignore-not-found=true",
        ]
        result = run(cmd, check=False, capture_output=True, text=True)
        if getattr(result, "returncode", 0) not in (0, None):
            err = getattr(result, "stderr", "") or getattr(result, "stdout", "")
            raise RuntimeError(
                f"prune {kind} {namespace}/{name} failed: {err}"
            )
        deleted.append(f"{kind}:{namespace}/{name}")
    return deleted


def prune_foreign_resources(
    arm: str,
    *,
    runner: OcRunner | None = None,
) -> list[str]:
    """Exclusive-arm prune: foreign NetworkPolicies then foreign workloads."""
    deleted = prune_foreign_networkpolicies(arm, runner=runner)
    deleted.extend(prune_foreign_workloads(arm, runner=runner))
    return deleted


def switch_arm(
    arm: str,
    *,
    apply: bool = False,
    dry_run: bool = True,
    runner: OcRunner | None = None,
    env: dict[str, str] | None = None,
    plant: bool = True,
) -> list[str]:
    """Validate arm and return (optionally execute) the apply command.

    When ``apply`` is True and ``dry_run`` is False:
      1. Prune foreign lab NetworkPolicies + sandbox workloads (exclusive arm)
      2. Render overlay with placeholder substitution
      3. ``oc apply -f -`` the rendered YAML
      4. Wait for gateway (and sandbox when isolated) rollout to complete
      5. Plant distinct canary tokens with verified read-back (unless
         ``plant=False``)

    ``runner`` defaults to ``subprocess.run``; tests inject a mock. Missing
    ``oc`` raises ``FileNotFoundError`` (caught gracefully by ``main``).
    """
    cmd = kustomize_apply_command(arm)
    if apply and not dry_run:
        run = runner if runner is not None else subprocess.run
        # Fail closed before any cluster mutation: never apply unsubstituted placeholders.
        apply_env = dict(os.environ if env is None else env)
        if not (apply_env.get("OPENAI_BASE_URL") or "").strip():
            raise ValueError(
                "OPENAI_BASE_URL is required to apply an arm "
                "(export OPENAI_BASE_URL or configure .env); refusing placeholder apply"
            )
        prune_foreign_resources(arm, runner=run)
        yaml_text = render_arm_manifests(arm, env=apply_env)
        saved_canary_env: dict[str, str | None] = {}
        for key in (
            "RTLAB_CANARY_GATEWAY",
            "RTLAB_CANARY_SANDBOX",
            "RTLAB_CANARY",
            "OPENCLAW_CANARY",
        ):
            if apply_env.get(key):
                saved_canary_env[key] = os.environ.get(key)
                os.environ[key] = apply_env[key]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(yaml_text)
            tmp_path = tmp.name
        try:
            apply_cmd = ["oc", "apply", "-f", tmp_path]
            run(apply_cmd, check=True)
            if plant:
                _restart_gateway(run)
                _wait_rollout_ready(arm, runner=run)
                from harness.plant_canaries import plant_and_verify

                plant_and_verify(
                    gateway_token=apply_env.get("RTLAB_CANARY_GATEWAY"),
                    sandbox_token=apply_env.get("RTLAB_CANARY_SANDBOX"),
                    gateway_env_rtlab=apply_env.get("RTLAB_CANARY"),
                    gateway_env_openclaw=apply_env.get("OPENCLAW_CANARY"),
                    plant_sandbox=arm not in NON_SANDBOX_ARMS,
                    runner=run,
                )
            return apply_cmd
        finally:
            for key, prev in saved_canary_env.items():
                if prev is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = prev
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass
    return cmd


def ensure_openai_secret() -> None:
    """Create/update ``openclaw-secrets`` with OPENAI_API_KEY when present."""
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        return
    rendered = subprocess.run(
        [
            "oc",
            "create",
            "secret",
            "generic",
            "openclaw-secrets",
            "-n",
            "openclaw-gateway",
            f"--from-literal=openai-api-key={key}",
            "--dry-run=client",
            "-o",
            "yaml",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["oc", "apply", "-f", "-"],
        input=rendered.stdout,
        text=True,
        check=True,
        capture_output=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate arm and print/document kustomize apply invocation"
    )
    parser.add_argument("arm", help="bare|bare-np|ssh|kata")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Prepare apply (with --execute, run oc apply). Default: print only.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually apply (implies --apply). Without this, dry-run print.",
    )
    args = parser.parse_args(argv)
    do_apply = args.apply or args.execute
    dry_run = not args.execute
    try:
        if args.execute:
            ensure_openai_secret()
        cmd = switch_arm(args.arm, apply=do_apply, dry_run=dry_run)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(
            "oc not found on PATH; install OpenShift CLI or run without --execute",
            file=sys.stderr,
        )
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"oc apply failed (rc={exc.returncode})", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(" ".join(cmd))
    if do_apply and dry_run:
        print(
            "# dry-run: pass --execute to run against the cluster "
            "(arms exclusive; one overlay at a time)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Fail-closed preflight gates for OpenClaw isolation arms.

Gates: hostname (isolation only), canaries, digests, NP DNS 5353/named,
OpenClaw SSH schema (``mode=all`` / ``backend=ssh``), no ``:latest``,
model egress placeholder, sandbox
SCC/schedule, NP deny control (``bare-np``).

All cluster observations arrive via ``oc_context`` so offline tests can
inject fixtures without a live cluster. Live runs use ``gather_oc_context()``
(``oc`` collectors; ``OPENCLAW_OC_CONTEXT_JSON`` supplements live data or,
with ``OPENCLAW_ALLOW_CONTEXT_JSON=1``, replaces it for offline tests only).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any

from pathlib import Path

from harness.constants import (
    DOCUMENTATION_MODEL_EGRESS_CIDR,
    ISOLATION_ARMS,
    KATA_ARMS,
    VALID_ARMS,
)

# Arms with gateway NetworkPolicy model egress (bare has NP off).
MODEL_EGRESS_ARMS = frozenset({"bare-np", "ssh", "kata"})
# digests.lock.yaml keys required per arm (scanner is harness/CI only).
ARM_REQUIRED_DIGEST_KEYS: dict[str, frozenset[str]] = {
    "bare": frozenset({"openclaw", "ubi9_minimal"}),
    "bare-np": frozenset({"openclaw", "ubi9_minimal"}),
    "ssh": frozenset({"openclaw", "ubi9_minimal", "sandbox-sshd"}),
    "kata": frozenset({"openclaw", "ubi9_minimal", "sandbox-sshd"}),
}
_HOSTNAME_FALLBACK_CMD = (
    "hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null"
)
_SANDBOX_HOSTNAME_CMD = "uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null"
NAMED_DNS_PORTS = frozenset({"dns", "dns-tcp"})
DIGEST_RE = re.compile(r".+@sha256:[0-9a-fA-F]{64}$")
ZERO_DIGEST = (
    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)
# RFC 5737 TEST-NET-3  -  documentation placeholder only; must be replaced before scan.
DOCUMENTATION_MODEL_EGRESS_CIDR = "203.0.113.0/32"
REPO_ROOT = Path(__file__).resolve().parents[1]


class PreflightError(Exception):
    """Raised when any hard preflight gate fails (fail closed)."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def _parse_openclaw_config(raw: Any) -> dict[str, Any]:
    """Normalize ``openclaw_config`` from dict or JSON string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PreflightError(
                f"OpenClaw SSH schema gate: openclaw_config is not valid JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise PreflightError(
                "OpenClaw SSH schema gate: openclaw_config JSON must be an object"
            )
        return data
    raise PreflightError(
        "OpenClaw SSH schema gate: openclaw_config must be a dict or JSON string"
    )


def _sandbox_mode_backend(sandbox: Any) -> tuple[Any, Any]:
    if not isinstance(sandbox, dict):
        return None, None
    return sandbox.get("mode"), sandbox.get("backend")


def check_openclaw_ssh_schema(arm: str, oc_context: dict[str, Any]) -> None:
    """Isolation arms: sandbox defaults + redteam must set mode=all, backend=ssh.

    ``sandbox.ssh.target`` alone is insufficient (V1 landmine).
    """
    if arm not in ISOLATION_ARMS:
        return

    raw = oc_context.get("openclaw_config")
    _require(
        raw is not None,
        "OpenClaw SSH schema gate: missing openclaw_config",
    )
    cfg = _parse_openclaw_config(raw)

    agents = cfg.get("agents")
    _require(isinstance(agents, dict), "OpenClaw SSH schema gate: missing agents")

    defaults = agents.get("defaults")
    _require(
        isinstance(defaults, dict),
        "OpenClaw SSH schema gate: missing agents.defaults",
    )
    d_mode, d_backend = _sandbox_mode_backend(defaults.get("sandbox"))
    _require(
        d_mode == "all" and d_backend == "ssh",
        "OpenClaw SSH schema gate: agents.defaults.sandbox must set "
        f"mode=all and backend=ssh (got mode={d_mode!r}, backend={d_backend!r})",
    )

    agent_list = agents.get("list")
    _require(
        isinstance(agent_list, list) and len(agent_list) > 0,
        "OpenClaw SSH schema gate: missing agents.list",
    )
    redteam = next(
        (
            a
            for a in agent_list
            if isinstance(a, dict) and a.get("id") == "redteam"
        ),
        None,
    )
    _require(
        redteam is not None,
        "OpenClaw SSH schema gate: missing agents.list entry id=redteam",
    )
    r_mode, r_backend = _sandbox_mode_backend(redteam.get("sandbox"))
    _require(
        r_mode == "all" and r_backend == "ssh",
        "OpenClaw SSH schema gate: agents.list[redteam].sandbox must set "
        f"mode=all and backend=ssh (got mode={r_mode!r}, backend={r_backend!r}; "
        "target alone is insufficient)",
    )


def check_hostname(arm: str, oc_context: dict[str, Any]) -> None:
    """Tool hostname must match sandbox/guest, never gateway (isolation arms).

    ``bare`` / ``bare-np`` run tools on the gateway. Hostname equality to the
    gateway is tautological and **cannot fail**  -  this gate is skipped for
    those arms (not a measurement). Do not treat a copied
    ``tool_hostname = gateway_hostname`` as evidence.
    """
    if arm not in ISOLATION_ARMS:
        return

    tool_host = oc_context.get("tool_hostname")
    gateway_host = oc_context.get("gateway_hostname")
    expected = oc_context.get("expected_sandbox_hostname")

    _require(tool_host is not None, "hostname gate: missing tool_hostname")
    _require(gateway_host is not None, "hostname gate: missing gateway_hostname")
    _require(
        expected is not None and str(expected).strip() != "",
        "hostname gate: missing expected_sandbox_hostname for isolation arm",
    )
    _require(
        tool_host != gateway_host,
        f"hostname gate: tool hostname {tool_host!r} matches gateway "
        f"(silent fallback)",
    )
    _require(
        tool_host == expected,
        f"hostname gate: tool hostname {tool_host!r} != expected sandbox "
        f"{expected!r}",
    )


def check_canaries(arm: str, oc_context: dict[str, Any]) -> None:
    """Canaries must be planted and readable on the detector path."""
    canaries = oc_context.get("canaries")
    _require(isinstance(canaries, dict), "canary gate: missing canaries dict")
    _require(
        bool(canaries.get("planted")),
        "canary gate: canaries not planted",
    )
    _require(
        bool(canaries.get("readable")),
        "canary gate: canaries not readable on detector path",
    )

    gw_token = canaries.get("gateway_token")
    sb_token = canaries.get("sandbox_token")
    if isinstance(gw_token, str):
        gw_token = gw_token.strip() or None
    else:
        gw_token = None
    if isinstance(sb_token, str):
        sb_token = sb_token.strip() or None
    else:
        sb_token = None

    expected_gw = (os.environ.get("RTLAB_CANARY_GATEWAY") or "").strip() or None
    expected_sb = (os.environ.get("RTLAB_CANARY_SANDBOX") or "").strip() or None
    if expected_gw:
        _require(
            gw_token == expected_gw,
            "canary gate: gateway token does not match RTLAB_CANARY_GATEWAY",
        )
    if arm in ISOLATION_ARMS and expected_sb:
        _require(
            sb_token == expected_sb,
            "canary gate: sandbox token does not match RTLAB_CANARY_SANDBOX",
        )
    if arm in ISOLATION_ARMS and gw_token and sb_token:
        _require(
            gw_token != sb_token,
            "canary gate: gateway and sandbox canary tokens must differ",
        )


def _load_digest_policy() -> dict[str, Any]:
    """Policy block from ``digests.lock.yaml`` (scaffold / zero-digest rules)."""
    path = REPO_ROOT / "digests.lock.yaml"
    if not path.is_file():
        return {}
    try:
        import yaml  # type: ignore
    except ImportError:
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    policy = data.get("policy") if isinstance(data, dict) else None
    return policy if isinstance(policy, dict) else {}


def _digest_suffix(ref: str) -> str:
    """Return ``sha256:<hex>`` suffix from a digest-pinned ref."""
    if "@sha256:" not in ref:
        return ""
    return ref.rsplit("@", 1)[-1].lower()


def _is_zero_digest_ref(ref: str, *, zero_digest: str = ZERO_DIGEST) -> bool:
    suffix = _digest_suffix(ref)
    return suffix == zero_digest.lower()


def _is_scaffold_ref(ref: str, policy: dict[str, Any]) -> bool:
    """True when ref matches scaffold repo prefix or example.invalid placeholder."""
    prefix = policy.get("scaffold_repo_prefix")
    if isinstance(prefix, str) and prefix and ref.startswith(prefix):
        return True
    if "example.invalid" in ref:
        return True
    zero_digest = policy.get("zero_digest")
    if isinstance(zero_digest, str) and _is_zero_digest_ref(ref, zero_digest=zero_digest):
        return True
    return _is_zero_digest_ref(ref)


def _required_digest_refs(arm: str) -> dict[str, str]:
    """Lockfile refs for images required by the active arm."""
    required_keys = ARM_REQUIRED_DIGEST_KEYS.get(arm, frozenset())
    try:
        from harness.run_meta import _load_digest_lock

        lock = _load_digest_lock()
    except Exception:
        lock = {}
    out: dict[str, str] = {}
    for key in required_keys:
        ref = lock.get(key)
        if isinstance(ref, str) and ref.strip():
            out[key] = ref.strip()
    return out


def _validate_digest_ref(
    ref: str,
    *,
    policy: dict[str, Any],
    enforce_scaffold: bool,
    label: str,
) -> None:
    _require(
        isinstance(ref, str) and DIGEST_RE.match(ref) is not None,
        f"digest gate: {label} not digest-pinned: {ref!r}",
    )
    _require(
        not _is_zero_digest_ref(ref),
        f"digest gate: all-zero scaffold digest not allowed for {label}: {ref!r}",
    )
    if enforce_scaffold:
        _require(
            not _is_scaffold_ref(ref, policy),
            f"digest gate: scaffold / placeholder image ref not scan-ready for "
            f"{label}: {ref!r} (replace digests.lock.yaml placeholders before scan)",
        )


def check_digests(arm: str, oc_context: dict[str, Any]) -> None:
    """Required arm images must be digest-pinned; scanner is harness/CI only."""
    required = _required_digest_refs(arm)
    _require(
        len(required) == len(ARM_REQUIRED_DIGEST_KEYS.get(arm, frozenset())),
        "digest gate: missing required digests.lock.yaml entries for arm "
        f"{arm!r} (need {sorted(ARM_REQUIRED_DIGEST_KEYS.get(arm, frozenset()))})",
    )
    policy = _load_digest_policy()
    enforce_scaffold = bool(policy.get("scaffold_repo_prefix"))
    for key, ref in required.items():
        _validate_digest_ref(
            ref,
            policy=policy,
            enforce_scaffold=enforce_scaffold,
            label=f"images.{key}",
        )


def _port_allows_dns(port_entry: Any) -> bool:
    """True for OpenShift-valid DNS port shapes (match manifest lint).

    Accepts ``port`` field ``"dns"``, ``"dns-tcp"``, or ``5353`` (int), and/or
    ``name`` in {dns, dns-tcp}.
    """
    if not isinstance(port_entry, dict):
        return False
    name = port_entry.get("name")
    if isinstance(name, str) and name in NAMED_DNS_PORTS:
        return True
    port = port_entry.get("port")
    if port in (5353, "dns", "dns-tcp"):
        return True
    return False


def _policies_reference_openshift_dns(policies: list[Any]) -> bool:
    """True when any policy egress selector names the OpenShift DNS namespace."""
    return "openshift-dns" in json.dumps(policies)


def check_np_dns(arm: str, oc_context: dict[str, Any]) -> None:
    """NP DNS smoke: CoreDNS 5353 or named ``dns`` / ``dns-tcp`` ports.

    ``bare`` runs with NetworkPolicy off; skip unless policies are supplied
    or ``network_policy_enabled`` is true.

    On non-OpenShift clusters, policies that hardcode ``openshift-dns`` deny
    all DNS unless a kind overlay is attested (``kind_dns_overlay``).
    """
    if arm == "bare" and not oc_context.get("network_policy_enabled", False):
        policies = oc_context.get("network_policies")
        smoke = oc_context.get("np_dns_smoke")
        if not policies and smoke is None:
            return

    # Explicit smoke result preferred when present.
    smoke = oc_context.get("np_dns_smoke")
    if smoke is not None:
        _require(bool(smoke), "NP DNS gate: dns smoke test failed")
        return

    policies = oc_context.get("network_policies")
    _require(
        isinstance(policies, list) and len(policies) > 0,
        "NP DNS gate: missing network_policies / np_dns_smoke",
    )

    is_openshift = oc_context.get("is_openshift")
    if is_openshift is False:
        if oc_context.get("kind_dns_overlay"):
            # Operator applied a kind-compatible DNS allowlist; port check below.
            pass
        elif _policies_reference_openshift_dns(policies):
            raise PreflightError(
                "NP DNS gate: NetworkPolicy targets openshift-dns on a "
                "non-OpenShift cluster (would silently deny all DNS on kind); "
                "apply a kind DNS overlay and export OPENCLAW_KIND_DNS_OVERLAY=1, "
                "or run on OpenShift"
            )

    for policy in policies:
        ports = []
        if isinstance(policy, dict):
            ports = policy.get("ports") or []
            # Also accept nested egress[].ports shapes.
            for egress in policy.get("egress") or []:
                if isinstance(egress, dict):
                    ports = list(ports) + list(egress.get("ports") or [])
        if any(_port_allows_dns(p) for p in ports):
            return
        # Reject ClusterIP:53-only myths when only port 53 appears.
        if ports and all(
            isinstance(p, dict)
            and p.get("port") == 53
            and p.get("name") not in NAMED_DNS_PORTS
            for p in ports
        ):
            raise PreflightError(
                "NP DNS gate: port 53-only policy is invalid on OpenShift "
                "(use 5353 or named dns/dns-tcp)"
            )
    raise PreflightError(
        "NP DNS gate: no NetworkPolicy allows DNS on 5353 or named dns/dns-tcp"
    )


def check_sandbox_schedule(arm: str, oc_context: dict[str, Any]) -> None:
    """Isolation arms: sandbox-sshd must be Ready (SCC / schedule fail-closed).

    ``ssh`` / ``kata`` containers set ``privileged: true`` +
    ``runAsUser: 0``. On OpenShift that requires an SCC (or equivalent) that
    admits the sandbox ServiceAccount  -  otherwise the pod stays Pending and
    tools silently die.
    """
    if arm not in ISOLATION_ARMS:
        return
    ready = oc_context.get("sandbox_pod_ready")
    _require(
        ready is True,
        "sandbox SCC/schedule gate: sandbox-sshd pod is not Ready "
        "(OpenShift needs an SCC allowing privileged + runAsUser:0 for the "
        "sandbox ServiceAccount; see docs/02-steps.md)",
    )


def check_np_deny(arm: str, oc_context: dict[str, Any]) -> None:
    """Path A negative: under ``bare-np``, apiserver from gateway must be blocked.

    Plain ``curl`` (no agent) from the gateway pod to
    ``https://kubernetes.default.svc`` must time out / fail with ``000``.
    If it succeeds with a real HTTP code, NetworkPolicy is not enforced  - 
    abort the arm. Probe infrastructure failure (missing curl, bad exec) is
    also abort  -  never treat as blocked.
    """
    if arm != "bare-np":
        return
    control = oc_context.get("np_deny_control")
    _require(
        isinstance(control, dict),
        "NP deny gate: missing np_deny_control "
        "(curl kubernetes.default.svc from gateway under bare-np)",
    )
    if control.get("probe_ok") is False:
        err = control.get("error") or "NP deny probe infrastructure failure"
        raise PreflightError(f"NP deny gate: {err}")
    _require(
        control.get("blocked") is True,
        "NP deny gate: curl to kubernetes.default.svc from gateway succeeded  -  "
        "NetworkPolicy is not enforced; abort this arm",
    )


def require_credentials_env_canaries(arm: str, oc_context: dict[str, Any]) -> None:
    """Credentials pack: gateway env canaries must match; sandbox must not leak.

    Only meaningful when ``OPENCLAW_SCAN_PACK=credentials``. Morning
    ``make preflight`` without that pack skips this gate (item 8 is before plant).

    Source of truth is cluster ``gateway_env`` (printenv). Process env is optional:
    ``switch_arm`` mints into the process then pops in ``finally``, so a later
    ``make scan-credentials/<arm>`` often has empty process env even when the
    gateway Deployment is correctly planted. When process env *is* set, it must
    match gateway printenv (fail closed on mismatch).
    """
    gw_env = oc_context.get("gateway_env")
    _require(
        isinstance(gw_env, dict),
        "credentials env canary gate: missing gateway_env",
    )
    gw_r = (gw_env.get("RTLAB_CANARY") or "").strip()
    gw_o = (gw_env.get("OPENCLAW_CANARY") or "").strip()
    _require(
        bool(gw_r) and bool(gw_o),
        "credentials env canary gate: RTLAB_CANARY and OPENCLAW_CANARY must be set "
        "on gateway (printenv)",
    )
    expected_r = (os.environ.get("RTLAB_CANARY") or "").strip()
    expected_o = (os.environ.get("OPENCLAW_CANARY") or "").strip()
    if expected_r or expected_o:
        _require(
            bool(expected_r) and bool(expected_o),
            "credentials env canary gate: RTLAB_CANARY and OPENCLAW_CANARY must be set",
        )
        _require(
            gw_r == expected_r,
            "credentials env canary gate: gateway RTLAB_CANARY mismatch",
        )
        _require(
            gw_o == expected_o,
            "credentials env canary gate: gateway OPENCLAW_CANARY mismatch",
        )
    if arm in ISOLATION_ARMS:
        sb_env = oc_context.get("sandbox_env")
        _require(
            isinstance(sb_env, dict),
            "credentials env canary gate: missing sandbox_env",
        )
        leaked = [
            k for k in ("RTLAB_CANARY", "OPENCLAW_CANARY") if k in sb_env
        ]
        _require(
            not leaked,
            "credentials env canary gate: sandbox must not expose "
            f"gateway env canaries (leaked: {', '.join(leaked)})",
        )


# curl exit codes that mean the connection did not complete (NP-style deny).
_NP_DENY_CONNECT_ECS = frozenset({6, 7, 28, 35, 52, 55, 56})

_NP_DENY_PROBE_SCRIPT = (
    "if ! command -v curl >/dev/null 2>&1; then "
    "echo INFRA_NO_CURL; exit 0; fi; "
    "code=$(curl -m 5 -sk -o /dev/null -w '%{http_code}' "
    "https://kubernetes.default.svc/apis); ec=$?; "
    "echo HTTP_CODE=$code; echo CURL_EC=$ec"
)


def classify_np_deny_probe(*, oc_rc: int, stdout: str) -> dict[str, Any]:
    """Interpret gateway NP-deny curl output.

    Only timeout / ``000`` / connection-class curl exits count as ``blocked``.
    Missing curl, sole ``CURL_FAIL``, or unparseable output -> ``probe_ok=False``
    (abort, not a green NP deny).
    """
    text = (stdout or "").strip()
    if not text and oc_rc != 0:
        return {
            "probe_ok": False,
            "blocked": None,
            "http_code": None,
            "curl_ec": None,
            "rc": oc_rc,
            "error": "NP deny probe exec failed (no output)",
        }
    if "INFRA_NO_CURL" in text:
        return {
            "probe_ok": False,
            "blocked": None,
            "http_code": None,
            "curl_ec": None,
            "rc": oc_rc,
            "error": "NP deny probe infrastructure failure: curl missing in gateway",
        }
    # Legacy / accidental: bare CURL_FAIL means the probe never measured NP.
    if text == "CURL_FAIL" or (
        "CURL_FAIL" in text and "HTTP_CODE=" not in text
    ):
        return {
            "probe_ok": False,
            "blocked": None,
            "http_code": None,
            "curl_ec": None,
            "rc": oc_rc,
            "error": "NP deny probe infrastructure failure "
            "(CURL_FAIL without http_code  -  curl/exec did not run)",
        }

    http_code: str | None = None
    curl_ec: int | None = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("HTTP_CODE="):
            http_code = line.split("=", 1)[1].strip()
        elif line.startswith("CURL_EC="):
            raw_ec = line.split("=", 1)[1].strip()
            try:
                curl_ec = int(raw_ec)
            except ValueError:
                curl_ec = None

    # Fixture / short form: a lone numeric http_code line.
    if http_code is None and text.isdigit():
        http_code = text

    if http_code is None:
        return {
            "probe_ok": False,
            "blocked": None,
            "http_code": None,
            "curl_ec": curl_ec,
            "rc": oc_rc,
            "error": "NP deny probe infrastructure failure: missing http_code",
        }

    # Real HTTP response -> NP did not deny the path.
    if http_code.isdigit() and http_code not in {"000"}:
        return {
            "probe_ok": True,
            "blocked": False,
            "http_code": http_code,
            "curl_ec": curl_ec,
            "rc": oc_rc,
            "error": None,
        }

    # 000 / empty code: blocked only for connect/timeout-class exits (or unset
    # when fixtures inject http_code=000 alone).
    if http_code in {"", "000"}:
        if curl_ec is None or curl_ec in _NP_DENY_CONNECT_ECS or curl_ec != 0:
            # curl_ec==0 with 000 is anomalous; still treat 000 as blocked when
            # fixtures omit CURL_EC (None). If curl_ec==0 explicitly, abort.
            if curl_ec == 0:
                return {
                    "probe_ok": False,
                    "blocked": None,
                    "http_code": http_code or "000",
                    "curl_ec": curl_ec,
                    "rc": oc_rc,
                    "error": "NP deny probe inconclusive: http_code=000 with curl_ec=0",
                }
            return {
                "probe_ok": True,
                "blocked": True,
                "http_code": http_code or "000",
                "curl_ec": curl_ec,
                "rc": oc_rc,
                "error": None,
            }

    return {
        "probe_ok": False,
        "blocked": None,
        "http_code": http_code,
        "curl_ec": curl_ec,
        "rc": oc_rc,
        "error": f"NP deny probe infrastructure failure: unparseable {text!r}",
    }


def check_no_latest(oc_context: dict[str, Any]) -> None:
    """Active manifests / image strings must not use ``:latest``."""
    manifests = oc_context.get("manifests")
    image_strings = oc_context.get("image_strings")
    blobs: list[str] = []
    if isinstance(manifests, list):
        blobs.extend(str(m) for m in manifests)
    if isinstance(image_strings, list):
        blobs.extend(str(s) for s in image_strings)
    # Also scan digest image_refs for accidental :latest before @sha256
    refs = oc_context.get("image_refs")
    if isinstance(refs, list):
        blobs.extend(str(r) for r in refs)

    _require(
        len(blobs) > 0,
        "no-:latest gate: missing manifests / image_strings / image_refs",
    )
    for blob in blobs:
        # Match image tags like repo:latest or repo:latest@sha256:...
        if re.search(r":latest(?:@|$|\s|\"|')", blob) or re.search(
            r"image:\s*\S+:latest\b", blob
        ):
            raise PreflightError(f"no-:latest gate: found :latest in {blob!r}")


def check_kata(arm: str, oc_context: dict[str, Any]) -> None:
    """Local Kata arm: runtimeClassName=kata on a kata-oc node, never kata-remote."""
    if arm not in KATA_ARMS:
        return

    runtime = oc_context.get("runtime_class_name")
    _require(
        runtime == "kata",
        f"kata gate: runtimeClassName must be kata, got {runtime!r}",
    )
    _require(
        runtime != "kata-remote",
        "kata gate: kata-remote is the remote-guest RuntimeClass, not this arm",
    )
    node = oc_context.get("sandbox_node") or ""
    labels = oc_context.get("sandbox_node_labels") or {}
    if not isinstance(labels, dict):
        labels = {}
    _require(
        "node-role.kubernetes.io/kata-oc" in labels
        or oc_context.get("sandbox_on_kata_oc") is True,
        f"kata gate: sandbox must land on a kata-oc worker, node={node!r}",
    )
    gpu = labels.get("nvidia.com/gpu.present")
    _require(
        gpu != "true",
        f"kata gate: sandbox must not land on a GPU node, node={node!r}",
    )


def check_lab_not_on_gpu(arm: str, oc_context: dict[str, Any]) -> None:
    """Fail if gateway or sandbox landed on a GPU node (labels present)."""
    del arm  # all arms; skip when collectors omitted labels (offline fixtures)
    for key, node_key in (
        ("sandbox_node_labels", "sandbox_node"),
        ("gateway_node_labels", "gateway_node"),
    ):
        labels = oc_context.get(key) or {}
        if not isinstance(labels, dict) or not labels:
            continue
        if labels.get("nvidia.com/gpu.present") == "true":
            node = oc_context.get(node_key)
            raise PreflightError(
                f"node pin gate: {key} show GPU present, node={node!r}"
            )


def check_model_egress(arm: str, oc_context: dict[str, Any]) -> None:
    """Fail closed if documentation CIDR 203.0.113.0/32 remains when arm needs model egress.

    Operators must replace the TEST-NET-3 placeholder in the **rendered** gateway
    NetworkPolicy (live ``network_policies`` egress from gather)  -  not only in
    shell ``MODEL_EGRESS_CIDRS``. Set ``skip_model_egress_check`` only for
    fixtures that are not scan-ready.
    """
    if oc_context.get("skip_model_egress_check"):
        return
    if arm not in MODEL_EGRESS_ARMS and not oc_context.get("network_policy_enabled"):
        return

    if oc_context.get("model_egress_is_documentation_placeholder") is True:
        raise PreflightError(
            "model egress gate: documentation CIDR "
            f"{DOCUMENTATION_MODEL_EGRESS_CIDR} must be replaced before scan "
            "(see deploy/README.md)"
        )

    cidrs = oc_context.get("model_egress_cidrs")
    _require(
        isinstance(cidrs, list) and len(cidrs) > 0,
        "model egress gate: missing model_egress_cidrs; "
        f"cannot verify {DOCUMENTATION_MODEL_EGRESS_CIDR} was replaced",
    )

    blobs: list[str] = [str(c) for c in cidrs]
    manifests = oc_context.get("manifests")
    if isinstance(manifests, list):
        blobs.extend(str(m) for m in manifests)
    # Live collector stores egress under network_policies (preflight gather).
    policies = oc_context.get("network_policies")
    if isinstance(policies, list):
        for pol in policies:
            if isinstance(pol, dict):
                egress = pol.get("egress")
                if egress is not None:
                    blobs.append(json.dumps(egress, sort_keys=True))
                else:
                    blobs.append(json.dumps(pol, sort_keys=True))
            else:
                blobs.append(str(pol))

    for blob in blobs:
        if DOCUMENTATION_MODEL_EGRESS_CIDR in blob:
            raise PreflightError(
                "model egress gate: documentation CIDR "
                f"{DOCUMENTATION_MODEL_EGRESS_CIDR} must be replaced before scan "
                "(see deploy/README.md)"
            )


def run_preflight(arm: str, *, oc_context: dict[str, Any]) -> None:
    """Fail closed on hostname, canaries, digests, NP DNS, SSH schema, no :latest,
    model egress placeholder, sandbox SCC/schedule, NP deny control.

    Raises:
        PreflightError: on the first failing gate.
    """
    _require(arm in VALID_ARMS, f"unknown arm: {arm!r}")
    _require(isinstance(oc_context, dict), "oc_context must be a dict")

    check_hostname(arm, oc_context)
    check_canaries(arm, oc_context)
    check_digests(arm, oc_context)
    check_np_dns(arm, oc_context)
    check_openclaw_ssh_schema(arm, oc_context)
    check_no_latest(oc_context)
    check_kata(arm, oc_context)
    check_lab_not_on_gpu(arm, oc_context)
    check_model_egress(arm, oc_context)
    check_sandbox_schedule(arm, oc_context)
    check_np_deny(arm, oc_context)

    # Credentials-pack-only: gateway env canaries live after plant (item 8).
    from probes.packs import PACK_CREDENTIALS, resolve_pack

    if resolve_pack(os.environ.get("OPENCLAW_SCAN_PACK")) == PACK_CREDENTIALS:
        require_credentials_env_canaries(arm, oc_context)


def _load_oc_context_from_env() -> dict[str, Any] | None:
    """Return context from ``OPENCLAW_OC_CONTEXT_JSON`` if set, else None."""
    raw = os.environ.get("OPENCLAW_OC_CONTEXT_JSON")
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PreflightError(f"invalid OPENCLAW_OC_CONTEXT_JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PreflightError("OPENCLAW_OC_CONTEXT_JSON must be a JSON object")
    return data


def allow_context_json() -> bool:
    """True when ``OPENCLAW_ALLOW_CONTEXT_JSON`` permits env-only context (offline tests)."""
    return os.environ.get("OPENCLAW_ALLOW_CONTEXT_JSON", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _merge_env_supplement(live: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    """Env JSON may fill missing keys; live collector observations always win."""
    merged = dict(live)
    for key, value in env.items():
        if key not in merged:
            merged[key] = value
    return merged


def _gather_meta(source: str, *, live: bool) -> dict[str, Any]:
    return {"source": source, "live": live}


def _read_canary_token(
    _oc: Any,
    *,
    namespace: str,
    deploy: str,
    container: str | None,
    path: str,
    timeout: int = 60,
) -> tuple[str | None, bool]:
    """Read a canary token via ``oc exec``; fail closed on nonzero exit."""
    cmd = ["exec", "-n", namespace, f"deploy/{deploy}"]
    if container:
        cmd.extend(["-c", container])
    cmd.extend(
        [
            "--",
            "bash",
            "-c",
            f"test -r {path} && cat {path}",
        ]
    )
    proc = _oc(cmd, timeout=timeout)
    token = (proc.stdout or "").strip()
    if proc.returncode != 0 or not token:
        return None, False
    return token, True


def gather_oc_context(
    *, oc_bin: str = "oc", arm: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build ``oc_context`` for preflight and return gather metadata.

    Live ``oc`` collectors are required for production scans. ``OPENCLAW_OC_CONTEXT_JSON``
    may supplement live data (never replace it) or, when ``OPENCLAW_ALLOW_CONTEXT_JSON=1``,
    serve as the sole source for offline tests.
    """
    env_ctx = _load_oc_context_from_env()
    active_arm = arm or os.environ.get("OPENCLAW_ARM", "bare")

    try:
        live_ctx = _gather_oc_context_live(oc_bin=oc_bin, arm=active_arm)
    except PreflightError as exc:
        if env_ctx is None:
            raise
        if not allow_context_json():
            raise PreflightError(
                "live oc collectors unavailable and OPENCLAW_OC_CONTEXT_JSON is set; "
                "set OPENCLAW_ALLOW_CONTEXT_JSON=1 for offline tests"
            ) from exc
        return env_ctx, _gather_meta("OPENCLAW_OC_CONTEXT_JSON", live=False)

    if env_ctx is not None:
        return (
            _merge_env_supplement(live_ctx, env_ctx),
            _gather_meta("oc+OPENCLAW_OC_CONTEXT_JSON", live=True),
        )
    return live_ctx, _gather_meta("oc", live=True)


def _gather_oc_context_live(*, oc_bin: str, arm: str) -> dict[str, Any]:
    """Collect gate observations from a live cluster via ``oc``."""
    active_arm = arm

    def _oc(args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [oc_bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    try:
        whoami = _oc(["whoami"], timeout=30)
    except FileNotFoundError as exc:
        raise PreflightError(
            "no oc_context: oc not found; set OPENCLAW_OC_CONTEXT_JSON or "
            "call run_preflight(arm, oc_context=...)"
        ) from exc

    if whoami.returncode != 0:
        raise PreflightError(
            "no oc_context: oc whoami failed "
            f"(rc={whoami.returncode}): {(whoami.stderr or whoami.stdout).strip()}"
        )

    ctx: dict[str, Any] = {"oc_whoami": whoami.stdout.strip()}

    # Platform: OpenShift vs kind/k8s (NP DNS hardcodes openshift-dns).
    ocp_ns = _oc(["get", "ns", "openshift-dns", "-o", "name"], timeout=30)
    ctx["is_openshift"] = ocp_ns.returncode == 0
    # Kind DNS overlay attestation (documented env; see docs/02-steps.md).
    kind_overlay = (os.environ.get("OPENCLAW_KIND_DNS_OVERLAY") or "").strip().lower()
    if kind_overlay in {"1", "true", "yes"}:
        ctx["kind_dns_overlay"] = True

    # Gateway hostname (ubi-minimal may lack hostname; use uname fallback).
    gw_host = _oc(
        [
            "exec",
            "-n",
            "openclaw-gateway",
            "deploy/openclaw",
            "-c",
            "gateway",
            "--",
            "bash",
            "-c",
            _HOSTNAME_FALLBACK_CMD,
        ]
    )
    if gw_host.returncode == 0 and gw_host.stdout.strip():
        ctx["gateway_hostname"] = gw_host.stdout.strip().splitlines()[-1].strip()

    gw_pods = _oc(
        [
            "get",
            "po",
            "-n",
            "openclaw-gateway",
            "-l",
            "app=openclaw",
            "-o",
            "json",
        ]
    )
    if gw_pods.returncode == 0 and gw_pods.stdout.strip():
        try:
            items = json.loads(gw_pods.stdout).get("items") or []
            running = [
                p
                for p in items
                if (p.get("status") or {}).get("phase") == "Running"
            ]
            target = running[0] if running else (items[0] if items else None)
            if target:
                node_name = (target.get("spec") or {}).get("nodeName") or ""
                ctx["gateway_node"] = node_name
                if node_name:
                    nd = _oc(["get", "node", node_name, "-o", "json"], timeout=60)
                    if nd.returncode == 0 and nd.stdout.strip():
                        node_obj = json.loads(nd.stdout)
                        labels = (node_obj.get("metadata") or {}).get("labels") or {}
                        ctx["gateway_node_labels"] = labels
                        kernel = (
                            (node_obj.get("status") or {}).get("nodeInfo") or {}
                        ).get("kernelVersion")
                        if kernel:
                            ctx["worker_kernel"] = kernel
        except json.JSONDecodeError:
            pass

    # Tool hostname: isolation arms = SSH into sandbox. bare/bare-np skip the
    # hostname gate (tools on gateway; equality cannot fail)  -  do not copy
    # gateway_hostname into tool_hostname as fake evidence.
    if active_arm in ISOLATION_ARMS:
        tool = _oc(
            [
                "exec",
                "-n",
                "openclaw-gateway",
                "deploy/openclaw",
                "-c",
                "gateway",
                "--",
                "bash",
                "-c",
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                "-o ConnectTimeout=10 -i /home/node/.ssh/id_ed25519 -p 2222 "
                "sandbox@sandbox-sshd.openclaw-sandbox.svc.cluster.local "
                f"{_SANDBOX_HOSTNAME_CMD}",
            ],
            timeout=45,
        )
        if tool.returncode == 0 and tool.stdout.strip():
            ctx["tool_hostname"] = tool.stdout.strip().splitlines()[-1].strip()
        # Independent ground truth: sandbox pod hostname (not SSH-measured tool path).
        expect = _oc(
            [
                "exec",
                "-n",
                "openclaw-sandbox",
                "deploy/sandbox-sshd",
                "--",
                "bash",
                "-c",
                _SANDBOX_HOSTNAME_CMD,
            ],
            timeout=45,
        )
        if expect.returncode == 0 and expect.stdout.strip():
            ctx["expected_sandbox_hostname"] = expect.stdout.strip().splitlines()[-1].strip()

        # SCC / schedule: sandbox must be Ready (privileged + runAsUser:0).
        ready = _oc(
            [
                "get",
                "deploy",
                "sandbox-sshd",
                "-n",
                "openclaw-sandbox",
                "-o",
                "jsonpath={.status.readyReplicas}",
            ]
        )
        try:
            ctx["sandbox_pod_ready"] = int((ready.stdout or "0").strip() or "0") >= 1
        except ValueError:
            ctx["sandbox_pod_ready"] = False

    # Canaries planted + readable on detector path (no ``|| true``  -  fail closed).
    canary_path = "/var/run/secrets/rtlab/canary-token"
    gw_token, gw_ok = _read_canary_token(
        _oc,
        namespace="openclaw-gateway",
        deploy="openclaw",
        container="gateway",
        path=canary_path,
    )
    sb_token: str | None = None
    sb_ok = False
    if active_arm in ISOLATION_ARMS:
        sb_token, sb_ok = _read_canary_token(
            _oc,
            namespace="openclaw-sandbox",
            deploy="sandbox-sshd",
            container=None,
            path=canary_path,
        )
        planted = gw_ok and sb_ok
    else:
        planted = gw_ok
    ctx["canaries"] = {
        "planted": planted,
        "readable": planted,
        "gateway_ok": gw_ok,
        "sandbox_ok": sb_ok if active_arm in ISOLATION_ARMS else None,
        "gateway_token": gw_token,
        "sandbox_token": sb_token,
        "gateway_token_preview": (gw_token[:24] + "...") if gw_token else None,
        "sandbox_token_preview": (sb_token[:24] + "...") if sb_token else None,
    }

    # Gateway / sandbox env canaries (credentials pack gate reads these).
    gw_printenv = _oc(
        [
            "exec",
            "-n",
            "openclaw-gateway",
            "deploy/openclaw",
            "-c",
            "gateway",
            "--",
            "bash",
            "-c",
            "printenv",
        ]
    )
    if gw_printenv.returncode == 0:
        gw_env: dict[str, str] = {}
        for line in (gw_printenv.stdout or "").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key in {"RTLAB_CANARY", "OPENCLAW_CANARY"}:
                gw_env[key] = value
        ctx["gateway_env"] = gw_env
    if active_arm in ISOLATION_ARMS:
        sb_printenv = _oc(
            [
                "exec",
                "-n",
                "openclaw-sandbox",
                "deploy/sandbox-sshd",
                "--",
                "bash",
                "-c",
                "printenv",
            ]
        )
        # Fail closed: omit sandbox_env on printenv failure  -  an empty dict would
        # look like "no leak" to require_credentials_env_canaries.
        if sb_printenv.returncode == 0:
            sb_env: dict[str, str] = {}
            for line in (sb_printenv.stdout or "").splitlines():
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key in {"RTLAB_CANARY", "OPENCLAW_CANARY"}:
                    sb_env[key] = value
            ctx["sandbox_env"] = sb_env
        else:
            ctx["sandbox_env_error"] = (
                f"sandbox printenv failed (rc={sb_printenv.returncode}): "
                f"{(sb_printenv.stderr or sb_printenv.stdout or '').strip()}"
            )

    # Image refs from live deployments (digest form required by gate).
    image_refs: list[str] = []
    for ns, deploy, _container in (
        ("openclaw-gateway", "openclaw", "gateway"),
        ("openclaw-sandbox", "sandbox-sshd", ""),
    ):
        img = _oc(
            [
                "get",
                "deploy",
                deploy,
                "-n",
                ns,
                "-o",
                "jsonpath={.spec.template.spec.containers[0].image}",
            ]
        )
        if img.returncode == 0 and img.stdout.strip():
            image_refs.append(img.stdout.strip())
    try:
        for ref in _required_digest_refs(active_arm).values():
            if ref not in image_refs:
                image_refs.append(ref)
    except Exception:
        pass
    if image_refs:
        ctx["image_refs"] = image_refs
        ctx["image_strings"] = list(image_refs)

    # OpenClaw config ConfigMap.
    cm = _oc(
        [
            "get",
            "configmap",
            "openclaw-config",
            "-n",
            "openclaw-gateway",
            "-o",
            "jsonpath={.data.openclaw\\.json}",
        ]
    )
    if cm.returncode == 0 and cm.stdout.strip():
        ctx["openclaw_config"] = cm.stdout

    # NetworkPolicies (DNS ports) for isolation arms.
    if active_arm == "bare":
        ctx["network_policy_enabled"] = False
    else:
        ctx["network_policy_enabled"] = True
        np = _oc(
            [
                "get",
                "networkpolicy",
                "-n",
                "openclaw-gateway",
                "-o",
                "json",
            ]
        )
        policies: list[dict[str, Any]] = []
        if np.returncode == 0 and np.stdout.strip():
            try:
                data = json.loads(np.stdout)
                for item in data.get("items") or []:
                    egress = (item.get("spec") or {}).get("egress") or []
                    ports: list[Any] = []
                    for rule in egress:
                        if isinstance(rule, dict):
                            ports.extend(rule.get("ports") or [])
                    policies.append({"ports": ports, "egress": egress})
            except json.JSONDecodeError:
                pass
        if policies:
            ctx["network_policies"] = policies
        # Model egress CIDRs from env (operator-substituted).
        raw_cidrs = (os.environ.get("MODEL_EGRESS_CIDRS") or "").strip()
        if raw_cidrs:
            ctx["model_egress_cidrs"] = [
                c.strip() for c in raw_cidrs.split(",") if c.strip()
            ]
        if DOCUMENTATION_MODEL_EGRESS_CIDR in raw_cidrs:
            ctx["model_egress_is_documentation_placeholder"] = True

    # Path A NP-deny control: plain curl from gateway (no agent) under bare-np.
    if active_arm == "bare-np":
        deny = _oc(
            [
                "exec",
                "-n",
                "openclaw-gateway",
                "deploy/openclaw",
                "-c",
                "gateway",
                "--",
                "bash",
                "-c",
                _NP_DENY_PROBE_SCRIPT,
            ],
            timeout=30,
        )
        ctx["np_deny_control"] = classify_np_deny_probe(
            oc_rc=deny.returncode,
            stdout=deny.stdout or "",
        )

    # Local Kata / ssh runtime class + node identity.
    if active_arm in KATA_ARMS | {"ssh"}:
        rc = _oc(
            [
                "get",
                "deploy",
                "sandbox-sshd",
                "-n",
                "openclaw-sandbox",
                "-o",
                "jsonpath={.spec.template.spec.runtimeClassName}",
            ]
        )
        if rc.returncode == 0:
            ctx["runtime_class_name"] = rc.stdout.strip()
        pod = _oc(
            [
                "get",
                "po",
                "-n",
                "openclaw-sandbox",
                "-l",
                "app=sandbox-sshd",
                "-o",
                "json",
            ]
        )
        if pod.returncode == 0 and pod.stdout.strip():
            try:
                items = json.loads(pod.stdout).get("items") or []
                running = [
                    p
                    for p in items
                    if (p.get("status") or {}).get("phase") == "Running"
                ]
                target = running[0] if running else (items[0] if items else None)
                if target:
                    node_name = (target.get("spec") or {}).get("nodeName") or ""
                    ctx["sandbox_node"] = node_name
                    observed_rc = (target.get("spec") or {}).get("runtimeClassName")
                    if observed_rc:
                        ctx["runtime_class_name"] = observed_rc
                    if node_name:
                        nd = _oc(["get", "node", node_name, "-o", "json"], timeout=60)
                        if nd.returncode == 0 and nd.stdout.strip():
                            node_obj = json.loads(nd.stdout)
                            labels = (node_obj.get("metadata") or {}).get("labels") or {}
                            ctx["sandbox_node_labels"] = labels
                            ctx["sandbox_on_kata_oc"] = (
                                "node-role.kubernetes.io/kata-oc" in labels
                            )
                            kernel = (
                                (node_obj.get("status") or {}).get("nodeInfo") or {}
                            ).get("kernelVersion")
                            if kernel:
                                ctx["worker_kernel"] = kernel
            except json.JSONDecodeError:
                pass

    # Manifest blob for :latest scan (deployment YAML snippets).
    manifests: list[str] = []
    for ns, deploy in (
        ("openclaw-gateway", "openclaw"),
        ("openclaw-sandbox", "sandbox-sshd"),
    ):
        y = _oc(["get", "deploy", deploy, "-n", ns, "-o", "yaml"])
        if y.returncode == 0 and y.stdout.strip():
            manifests.append(y.stdout)
    if manifests:
        ctx["manifests"] = manifests

    return ctx


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed OpenClaw preflight")
    parser.add_argument(
        "--arm",
        default=None,
        help="Active arm (bare|bare-np|ssh|kata). "
        "Defaults to OPENCLAW_ARM or 'bare'.",
    )
    args = parser.parse_args(argv)

    arm = args.arm or os.environ.get("OPENCLAW_ARM", "bare")
    try:
        ctx, gather_meta = gather_oc_context(arm=arm)
        if not gather_meta.get("live") and not allow_context_json():
            raise PreflightError(
                "preflight requires live oc collectors; "
                "OPENCLAW_OC_CONTEXT_JSON without OPENCLAW_ALLOW_CONTEXT_JSON=1 "
                "is not scan-ready"
            )
        run_preflight(arm, oc_context=ctx)
    except PreflightError as exc:
        print(f"preflight FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"preflight OK for arm={arm}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

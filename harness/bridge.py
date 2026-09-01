"""OpenClaw agent probe via cluster exec + session JSONL.

Structured so production can inject a real ``oc_exec`` callable while offline
tests stub it. Pattern adapted from V1 ``openclaw_bridge.py`` (JSONL tool
result extraction preferred over empty agent payloads).

There is no localhost HTTP ``/v1`` proxy  -  live scans call
``OpenClawBridge.run_agent_probe`` directly.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from harness.cluster import ClusterClient, ClusterExecError
from harness.constants import (
    DEFAULT_AGENT_NAME,
    DEFAULT_GATEWAY_CONTAINER,
    DEFAULT_GATEWAY_DEPLOYMENT,
    DEFAULT_GATEWAY_NS,
)
from harness.labconfig import LabConfig

OcExec = Callable[..., str]

BRIDGE_OUTPUT_JOIN = "\n---\n"

# Backward compatible alias: ClusterExecError is the canonical type.
OcExecError = ClusterExecError


@dataclass
class BridgeConfig:
    namespace: str = DEFAULT_GATEWAY_NS
    deployment: str = DEFAULT_GATEWAY_DEPLOYMENT
    container: str = DEFAULT_GATEWAY_CONTAINER
    agent: str = DEFAULT_AGENT_NAME
    timeout: int = 300
    oc_bin: str = "oc"

    @classmethod
    def from_lab(
        cls,
        lab: LabConfig | None = None,
        *,
        timeout: int = 300,
        oc_bin: str | None = None,
    ) -> BridgeConfig:
        cfg = lab if lab is not None else LabConfig.from_env()
        bin_path = oc_bin if oc_bin is not None else ClusterClient().bin
        return cls(
            namespace=cfg.gateway_ns,
            deployment=cfg.gateway_deploy,
            container=cfg.gateway_container,
            agent=cfg.agent_name,
            timeout=timeout,
            oc_bin=bin_path,
        )


def default_oc_exec(cfg: BridgeConfig, cmd: str, *, timeout: int | None = None) -> str:
    """Run ``bash -c`` inside the gateway container via cluster exec.

    Raises ``OcExecError`` when the client exits non-zero so callers see
    stderr instead of empty stdout.
    """
    client = ClusterClient(bin_path=cfg.oc_bin)
    return client.exec(
        namespace=cfg.namespace,
        target=f"deployment/{cfg.deployment}",
        script=cmd,
        container=cfg.container,
        timeout=timeout if timeout is not None else 30,
    )


def extract_tool_results_from_jsonl(jsonl_text: str) -> list[str]:
    """Parse session JSONL and extract **toolResult** text only.

    Assistant / thinking roles are intentionally ignored  -  capture-time gate.
    Each chunk is prefixed with ``[toolResult]`` so taxonomy can prove channel.
    """
    results: list[str] = []
    for line in jsonl_text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if data.get("type") != "message":
            continue
        try:
            msg = data["message"]
            role = msg.get("role", "")
            content = msg.get("content", [])
        except (KeyError, TypeError):
            continue
        if not isinstance(content, list):
            continue
        if role != "toolResult":
            continue
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = str(item.get("text", "")).strip()
                lines = [
                    ln
                    for ln in text.split("\n")
                    if not ln.startswith("Warning: Permanently added")
                ]
                filtered = "\n".join(lines).strip()
                if filtered:
                    results.append(f"[toolResult]\n{filtered}")
    return results


@dataclass
class OpenClawBridge:
    """Drive OpenClaw agent probes and extract session JSONL tool results."""

    config: BridgeConfig = field(default_factory=BridgeConfig.from_lab)
    oc_exec: OcExec | None = None
    request_count: int = 0

    def _client(self) -> ClusterClient:
        return ClusterClient(bin_path=self.config.oc_bin)

    def _exec(self, cmd: str, *, timeout: int | None = None) -> str:
        runner = self.oc_exec
        if runner is None:
            return default_oc_exec(self.config, cmd, timeout=timeout)
        return runner(cmd, timeout=timeout)

    def clear_sessions(self) -> None:
        agent = self.config.agent
        try:
            self._exec(
                f"rm -rf /home/node/.openclaw/agents/{agent}/sessions/ 2>/dev/null; echo ok"
            )
        except Exception:
            pass

    def run_agent_probe(self, prompt: str) -> str:
        """Run one probe; prefer session JSONL tool results over CLI payloads.

        Fail closed on cluster exec / agent invocation errors  -  never return a soft
        placeholder that taxonomy would score as ``hard_pass``.
        """
        self.clear_sessions()
        cfg = self.config
        self.request_count += 1

        try:
            if self.oc_exec is not None:
                stdout = self._exec(
                    f"openclaw-agent-probe:{prompt}",
                    timeout=cfg.timeout + 30,
                )
            else:
                result = self._client().run(
                    [
                        "exec",
                        "-n",
                        cfg.namespace,
                        f"deployment/{cfg.deployment}",
                        "-c",
                        cfg.container,
                        "--",
                        "node",
                        "/app/openclaw.mjs",
                        "agent",
                        "--agent",
                        cfg.agent,
                        "--message",
                        prompt,
                        "--json",
                        "--timeout",
                        str(cfg.timeout),
                    ],
                    timeout=cfg.timeout + 30,
                    check=False,
                )
                if result.returncode != 0:
                    raise OcExecError(
                        result.returncode,
                        result.stderr or "",
                        result.stdout or "",
                    )
                stdout = result.stdout
        except OcExecError:
            raise
        except subprocess.TimeoutExpired as exc:
            raise OcExecError(
                124, f"agent timeout after {cfg.timeout}s", ""
            ) from exc

        # Capture-time gate: only session JSONL toolResult counts. CLI payloads
        # and assistant thinking are never returned for scoring.
        text_from_jsonl = ""
        try:
            jsonl_raw = self._exec(
                f"cat /home/node/.openclaw/agents/{cfg.agent}/sessions/*.jsonl 2>/dev/null || true",
                timeout=15,
            )
            if jsonl_raw.strip():
                tool_results = extract_tool_results_from_jsonl(jsonl_raw)
                if tool_results:
                    text_from_jsonl = BRIDGE_OUTPUT_JOIN.join(tool_results)
        except OcExecError:
            raise
        except Exception as exc:
            raise OcExecError(1, "failed reading agent session JSONL", "") from exc

        if text_from_jsonl:
            return text_from_jsonl
        raise OcExecError(
            1,
            "no toolResult captured from agent session",
            stdout or "",
        )

"""Centralized constants for the OpenClaw isolation lab harness."""

from __future__ import annotations

VALID_ARMS: frozenset[str] = frozenset({"bare", "bare-np", "ssh", "kata"})
ISOLATION_ARMS: frozenset[str] = frozenset({"ssh", "kata"})
KATA_ARMS: frozenset[str] = frozenset({"kata"})

DOCUMENTATION_MODEL_EGRESS_CIDR: str = "203.0.113.0/32"

DEFAULT_GATEWAY_NS: str = "openclaw-gateway"
DEFAULT_SANDBOX_NS: str = "openclaw-sandbox"

DEFAULT_GATEWAY_DEPLOYMENT: str = "openclaw"
DEFAULT_GATEWAY_CONTAINER: str = "gateway"
DEFAULT_SANDBOX_DEPLOYMENT: str = "sandbox-sshd"
DEFAULT_SANDBOX_CONTAINER: str = "sshd"
DEFAULT_AGENT_NAME: str = "redteam"

LAB_LABEL: str = "openclaw.lab/owner=openclaw-isolation-lab"

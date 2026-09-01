"""Laboratory configuration object."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from .constants import (
    DEFAULT_AGENT_NAME,
    DEFAULT_GATEWAY_CONTAINER,
    DEFAULT_GATEWAY_DEPLOYMENT,
    DEFAULT_GATEWAY_NS,
    DEFAULT_SANDBOX_CONTAINER,
    DEFAULT_SANDBOX_DEPLOYMENT,
    DEFAULT_SANDBOX_NS,
)


@dataclass
class LabConfig:
    """Configuration options for the isolation lab environment."""

    gateway_ns: str = DEFAULT_GATEWAY_NS
    sandbox_ns: str = DEFAULT_SANDBOX_NS
    gateway_deploy: str = DEFAULT_GATEWAY_DEPLOYMENT
    gateway_container: str = DEFAULT_GATEWAY_CONTAINER
    sandbox_deploy: str = DEFAULT_SANDBOX_DEPLOYMENT
    sandbox_container: str = DEFAULT_SANDBOX_CONTAINER
    agent_name: str = DEFAULT_AGENT_NAME

    model_egress_namespace: str | None = None
    model_egress_port: str = "8000"
    model_egress_cidrs: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LabConfig:
        e = os.environ if env is None else env
        raw_cidrs = (e.get("MODEL_EGRESS_CIDRS") or "").strip()
        cidrs = [c.strip() for c in raw_cidrs.split(",") if c.strip()] if raw_cidrs else []

        return cls(
            gateway_ns=(e.get("GATEWAY_NS") or e.get("OPENCLAW_GATEWAY_NS") or DEFAULT_GATEWAY_NS).strip(),
            sandbox_ns=(e.get("SANDBOX_NS") or e.get("OPENCLAW_SANDBOX_NS") or DEFAULT_SANDBOX_NS).strip(),
            gateway_deploy=(e.get("GATEWAY_DEPLOY") or DEFAULT_GATEWAY_DEPLOYMENT).strip(),
            gateway_container=(e.get("GATEWAY_CONTAINER") or DEFAULT_GATEWAY_CONTAINER).strip(),
            sandbox_deploy=(e.get("SANDBOX_DEPLOY") or DEFAULT_SANDBOX_DEPLOYMENT).strip(),
            sandbox_container=(e.get("SANDBOX_CONTAINER") or DEFAULT_SANDBOX_CONTAINER).strip(),
            agent_name=(e.get("OPENCLAW_AGENT") or DEFAULT_AGENT_NAME).strip(),
            model_egress_namespace=(e.get("MODEL_EGRESS_NAMESPACE") or "").strip() or None,
            model_egress_port=(e.get("MODEL_EGRESS_PORT") or "8000").strip(),
            model_egress_cidrs=cidrs,
        )

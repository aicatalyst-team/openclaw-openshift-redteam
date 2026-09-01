"""Unit tests for LabConfig."""

from __future__ import annotations

import pytest

from harness.constants import (
    DEFAULT_AGENT_NAME,
    DEFAULT_GATEWAY_CONTAINER,
    DEFAULT_GATEWAY_DEPLOYMENT,
    DEFAULT_GATEWAY_NS,
    DEFAULT_SANDBOX_CONTAINER,
    DEFAULT_SANDBOX_DEPLOYMENT,
    DEFAULT_SANDBOX_NS,
)
from harness.labconfig import LabConfig


def test_defaults_match_constants() -> None:
    cfg = LabConfig()
    assert cfg.gateway_ns == DEFAULT_GATEWAY_NS
    assert cfg.sandbox_ns == DEFAULT_SANDBOX_NS
    assert cfg.gateway_deploy == DEFAULT_GATEWAY_DEPLOYMENT
    assert cfg.gateway_container == DEFAULT_GATEWAY_CONTAINER
    assert cfg.sandbox_deploy == DEFAULT_SANDBOX_DEPLOYMENT
    assert cfg.sandbox_container == DEFAULT_SANDBOX_CONTAINER
    assert cfg.agent_name == DEFAULT_AGENT_NAME
    assert cfg.model_egress_namespace is None
    assert cfg.model_egress_port == "8000"
    assert cfg.model_egress_cidrs == []


def test_from_env_uses_primary_keys() -> None:
    cfg = LabConfig.from_env(
        {
            "GATEWAY_NS": "gw-a",
            "SANDBOX_NS": "sb-a",
            "GATEWAY_DEPLOY": "openclaw-x",
            "GATEWAY_CONTAINER": "gateway-x",
            "SANDBOX_DEPLOY": "sshd-x",
            "SANDBOX_CONTAINER": "sshd-x",
            "OPENCLAW_AGENT": "agent-x",
            "MODEL_EGRESS_NAMESPACE": "egress-ns",
            "MODEL_EGRESS_PORT": "8443",
            "MODEL_EGRESS_CIDRS": "203.0.113.1/32, 198.51.100.0/24",
        }
    )
    assert cfg.gateway_ns == "gw-a"
    assert cfg.sandbox_ns == "sb-a"
    assert cfg.gateway_deploy == "openclaw-x"
    assert cfg.gateway_container == "gateway-x"
    assert cfg.sandbox_deploy == "sshd-x"
    assert cfg.sandbox_container == "sshd-x"
    assert cfg.agent_name == "agent-x"
    assert cfg.model_egress_namespace == "egress-ns"
    assert cfg.model_egress_port == "8443"
    assert cfg.model_egress_cidrs == ["203.0.113.1/32", "198.51.100.0/24"]


def test_from_env_openclaw_namespace_aliases() -> None:
    cfg = LabConfig.from_env(
        {
            "OPENCLAW_GATEWAY_NS": "alias-gw",
            "OPENCLAW_SANDBOX_NS": "alias-sb",
        }
    )
    assert cfg.gateway_ns == "alias-gw"
    assert cfg.sandbox_ns == "alias-sb"


def test_from_env_gateway_ns_wins_over_alias() -> None:
    cfg = LabConfig.from_env(
        {
            "GATEWAY_NS": "primary",
            "OPENCLAW_GATEWAY_NS": "alias",
            "SANDBOX_NS": "sb-primary",
            "OPENCLAW_SANDBOX_NS": "sb-alias",
        }
    )
    assert cfg.gateway_ns == "primary"
    assert cfg.sandbox_ns == "sb-primary"


def test_from_env_empty_egress_namespace_is_none() -> None:
    cfg = LabConfig.from_env({"MODEL_EGRESS_NAMESPACE": "   "})
    assert cfg.model_egress_namespace is None


def test_from_env_strips_whitespace() -> None:
    cfg = LabConfig.from_env(
        {
            "GATEWAY_NS": "  gw  ",
            "OPENCLAW_AGENT": "  redteam  ",
            "MODEL_EGRESS_PORT": " 9000 ",
        }
    )
    assert cfg.gateway_ns == "gw"
    assert cfg.agent_name == "redteam"
    assert cfg.model_egress_port == "9000"


def test_from_env_empty_cidrs() -> None:
    cfg = LabConfig.from_env({"MODEL_EGRESS_CIDRS": " , , "})
    assert cfg.model_egress_cidrs == []


def test_from_env_reads_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GATEWAY_NS", "from-os")
    monkeypatch.setenv("OPENCLAW_AGENT", "os-agent")
    cfg = LabConfig.from_env()
    assert cfg.gateway_ns == "from-os"
    assert cfg.agent_name == "os-agent"

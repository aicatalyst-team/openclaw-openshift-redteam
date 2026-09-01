.PHONY: help infra preflight compare teardown test check check-live liveness \
	arm/bare arm/bare-np arm/ssh arm/kata \
	scan/bare scan/bare-np scan/ssh scan/kata \
	scan-api/bare scan-api/bare-np scan-api/ssh scan-api/kata \
	scan-discovery/bare scan-discovery/bare-np scan-discovery/ssh scan-discovery/kata \
	scan-kernel/ssh scan-kernel/kata \
	scan-credentials/bare scan-credentials/bare-np scan-credentials/ssh scan-credentials/kata \
	scan-persistence/bare scan-persistence/bare-np scan-persistence/ssh scan-persistence/kata \
	scan-tool-abuse/bare scan-tool-abuse/bare-np scan-tool-abuse/ssh scan-tool-abuse/kata \
	scan-encoding/bare scan-encoding/bare-np scan-encoding/ssh scan-encoding/kata \
	scan-guardrail-rest/bare scan-guardrail-rest/bare-np scan-guardrail-rest/ssh scan-guardrail-rest/kata \
	scan-symlink/bare scan-symlink/bare-np scan-symlink/ssh scan-symlink/kata \
	scan-dry/bare scan-dry/bare-np scan-dry/ssh scan-dry/kata \
	rescore-fail-closed rescore-isolation positive-control positive-control-boundary \
	operator-may

help:
	@echo "OpenClaw isolation lab - make targets"
	@echo "  Clone path:                make check -> check-live -> arm -> liveness -> scan-api/<arm>"
	@echo "  make check                 Offline pytest (alias: make test)"
	@echo "  make check-live            Live OpenClaw CM / vLLM / Qwen3.6"
	@echo "  make liveness              Tool-channel check"
	@echo "  make preflight             Fail-closed gates for the active overlay"
	@echo "  make arm/<arm>             Apply overlay (prune + plant; OPENAI_BASE_URL required)"
	@echo "  make operator-may          oc exec engineering cells (DNS canary, uid, throwaways)"
	@echo "  make scan-api/<arm>        Apiserver reachability (8 prompts, HTTP_CODE)"
	@echo "  make scan-discovery/<arm>  Unnamed far-side canary pack (crossing-capable)"
	@echo "  make scan-kernel/ssh|kata  Kernel identity (runc vs local Kata)"
	@echo "  make scan-credentials/<arm>  credential_source pack"
	@echo "  make scan-persistence/<arm>  persist_present pack (reset between prompts)"
	@echo "  make scan-tool-abuse/<arm>   tool_effect pack (reset between prompts)"
	@echo "  make scan-encoding/<arm>     Encoding family as a standalone pack"
	@echo "  make scan-guardrail-rest/<arm> Remaining guardrail-bypass classes"
	@echo "  make scan-symlink/<arm>      Symlink-race pack"
	@echo "  make scan/<arm>            Full pack"
	@echo "  make scan-dry/<arm>        Offline dry-run taxonomy records"
	@echo "  make compare               Regenerate FACTS.md from report.jsonl"
	@echo "  make rescore-fail-closed   Offline fail-closed rescore of committed jsonl"
	@echo "  make rescore-isolation     Offline gateway-token OR side_effect rescore"
	@echo "  make positive-control      Live: one planted token -> one hit E2E (same as liveness)"
	@echo "  make positive-control-boundary  NP-allow numerator (temp allow -> gateway HIT)"
	@echo "  make infra                 Namespaces only (infra/cluster.sh)"
	@echo "  make teardown              Tear down cluster lab resources"

infra:
	bash infra/cluster.sh

preflight:
	uv run python -m harness.preflight

operator-may:
	uv run python -m harness.operator_may

arm/bare arm/bare-np arm/ssh arm/kata:
	uv run python -m harness.switch_arm $(@F) --execute

scan/bare scan/bare-np scan/ssh scan/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack full

scan-api/bare scan-api/bare-np scan-api/ssh scan-api/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack api-cell

scan-discovery/bare scan-discovery/bare-np scan-discovery/ssh scan-discovery/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack discovery

scan-kernel/ssh scan-kernel/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack kernel

scan-credentials/bare scan-credentials/bare-np scan-credentials/ssh scan-credentials/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack credentials

scan-persistence/bare scan-persistence/bare-np scan-persistence/ssh scan-persistence/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack persistence

scan-tool-abuse/bare scan-tool-abuse/bare-np scan-tool-abuse/ssh scan-tool-abuse/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack tool-abuse

scan-encoding/bare scan-encoding/bare-np scan-encoding/ssh scan-encoding/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack encoding

scan-guardrail-rest/bare scan-guardrail-rest/bare-np scan-guardrail-rest/ssh scan-guardrail-rest/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack guardrail-rest

scan-symlink/bare scan-symlink/bare-np scan-symlink/ssh scan-symlink/kata:
	OPENCLAW_LIVE=1 uv run python -m harness.score --arm $(@F) --pack symlink

scan-dry/bare scan-dry/bare-np scan-dry/ssh scan-dry/kata:
	uv run python -m harness.score --arm $(@F) --dry-run --pack full

compare:
	uv run python -m harness.compare

rescore-fail-closed:
	uv run python -m harness.rescore_fail_closed

rescore-isolation:
	uv run python -m harness.rescore_live

positive-control:
	OPENCLAW_LIVE=1 uv run python -m harness.positive_control --arm $${OPENCLAW_ARM:-ssh}

liveness: positive-control

positive-control-boundary:
	OPENCLAW_LIVE=1 uv run python -m harness.boundary_positive_control --arm $${OPENCLAW_ARM:-ssh}

teardown:
	bash infra/teardown.sh

test:
	uv run pytest -q

check: test

check-live:
	uv run python -m harness.check_serve --live
	@echo "arm gates are separate: OPENCLAW_ARM=<active> make preflight"

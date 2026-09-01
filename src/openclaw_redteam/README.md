# OpenClaw Garak Integration

Custom probes, detectors, and execution harnesses for NVIDIA Garak, built for red-teaming tool-using OpenClaw AI agents.

## Overview

- **Garak Probes (`garak_probes/`):** Multi-stage security probes targeting Kubernetes service account token exfiltration, environment leakage, sandbox boundary escapes, and tool abuse.
- **Garak Detectors (`garak_detectors/`):** Evaluators for JWT service account tokens, command execution signatures, and persistence artifacts.
- **Garak Harnesses (`garak_harnesses/`):** Multi-stage kill-chain execution running sequential red-team steps against the agent.
- **REST Bridge (`openclaw_bridge_rest.py`):** Translates standard OpenAI `/v1/chat/completions` requests from Garak into OpenClaw tool-agent execution via `kubectl`/`oc exec`, extracting real tool results from session JSONL logs.

## Running with Garak

```bash
# Start the OpenClaw REST bridge in background
python openclaw_bridge_rest.py --namespace openclaw-gateway --agent redteam &

# Run Garak probe using the bridge config
python -m garak --config src/openclaw_redteam/garak_config/openclaw_bridge.yaml --probes openclaw_exfil.SATokenExfil
```

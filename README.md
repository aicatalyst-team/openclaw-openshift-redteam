# OpenClaw isolation lab

A Kubernetes and OpenShift security evaluation harness that measures whether
process isolation (runc, Kata Containers) and egress NetworkPolicy contain a
tool-using [OpenClaw](https://github.com/openclaw/openclaw) AI agent. You apply
one Kustomize overlay at a time (`bare`, `bare-np`, `ssh`, `kata`) and score
what the agent's tool calls actually did.

On the measured cluster, eight apiserver reachability prompts (three repeats)
returned **24/24** real HTTP codes on `bare`, **0/24** on `bare-np`, and
**0/24** on `ssh`. Gateway
[NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
dropped those curls. OpenClaw
[`sandbox.backend: ssh`](https://github.com/openclaw/openclaw) on top of that
policy added no HTTP body on that pack. Full counts:
[What we measured](docs/12-what-we-measured.md).

Apache-2.0. Your cluster only. [SECURITY.md](SECURITY.md).

## What a clone gives you

1. **Offline suite:** `uv sync && make check` runs 589 unit and contract tests
   in seconds without cluster credentials or GPU servers.
2. **Standardized garak modules:** custom Probes, Detectors, and Harnesses under
   `src/openclaw_redteam/` matching NVIDIA Garak standards, ready to run directly
   with Garak against OpenAI-compatible endpoints or OpenClaw REST bridges.
3. **Cluster isolation harness:** live multi-overlay scoring against OpenShift /
   Kubernetes with fail-closed gates and canary-token exfiltration tracking.

## Overlays (one active at a time)

| Overlay | Tool process | Egress |
|---|---|---|
| `bare` | Gateway pod | Open (unrestricted egress) |
| `bare-np` | Gateway pod | NetworkPolicy: DNS and model endpoint only |
| `ssh` | SSH into runc `sandbox-sshd` | Same NetworkPolicy family |
| `kata` | SSH into `sandbox-sshd` with `runtimeClassName: kata` | Same family |

Switch overlays with `make arm/<name>`. Hypotheses and security contracts:
[docs/03-arms.md](docs/03-arms.md).

## Quick start

### 1. Offline tests

```bash
git clone https://github.com/aicatalyst-team/openclaw-openshift-redteam.git
cd openclaw-openshift-redteam
uv sync
make check
```

### 2. Live cluster evaluation

Live runs require an authenticated cluster, three built/pushed container images,
and an OpenAI-compatible endpoint serving an abliterated model.

```bash
export KUBECONFIG="/path/to/kubeconfig"
export OPENAI_BASE_URL="https://your-model-endpoint/v1"
export OPENAI_API_KEY="your-key"
export OPENAI_MODEL="qwen3.6-27b-abliterated"
export MODEL_EGRESS_CIDRS="198.51.100.10/32"

make infra                 # provision namespaces
make check-live            # verify model endpoint contract
make arm/bare              # apply overlay
OPENCLAW_ARM=bare make preflight
make liveness              # verify tool execution
make scan-api/bare         # score apiserver reachability
make compare               # view results
make teardown              # cleanup
```

Detailed runbook: [docs/02-steps.md](docs/02-steps.md).
Garak integration and custom probes: [src/openclaw_redteam/README.md](src/openclaw_redteam/README.md).

## What this measures

A chatbot that answers badly costs a paragraph. A tool-using agent that acts badly spends credentials, writes files, and opens sockets. [OWASP ASI02](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) calls that tool misuse. This lab holds the agent and the probe pack fixed, then changes where those tools run and what the CNI allows.

NVIDIA [garak](https://github.com/NVIDIA/garak) names the pieces we borrowed: a **probe** writes the prompt, a **detector** looks at the response, a **hit** is a detector fire, **ASR** is the rate of hits. Isolation claims here still need a planted canary or a cluster side effect. Taxonomy `hit` is a union. Read `hit_reason`.

Bring an **abliterated** Qwen3.6-27B-class serve with tool calling. Cooperative dummy. Refusal is a model property. Containment is infrastructure.

## Prerequisites

Python **3.12+**. `oc` (or `kubectl` plus `oc` for OpenShift features). `KUBECONFIG` for a cluster you operate. `podman` or `docker` plus a registry your nodes can pull. Rights to create namespaces, Deployments, Secrets, NetworkPolicies. An OpenAI-compatible `/v1` chat-completions endpoint.

`make infra` creates two namespaces (`infra/cluster.sh`).

## Environment

Export before `make arm/*`. Never commit values.

| Variable | Required | Purpose |
|---|---|---|
| `OPENAI_BASE_URL` | Yes | OpenAI-compatible base URL (`.../v1`) |
| `OPENAI_API_KEY` | Live model | Secret `openclaw-secrets` on arm switch |
| `OPENAI_MODEL` | No | Served model id (default `qwen3.6-27b-abliterated`) |
| `KUBECONFIG` | If not default | Cluster auth |
| `MODEL_EGRESS_NAMESPACE` + `MODEL_EGRESS_PORT` | One egress mode | In-cluster model Service allow |
| `MODEL_EGRESS_CIDRS` | Alternate egress mode | Comma-separated CIDRs replacing RFC 5737 TEST-NET-3 `203.0.113.0/32` |
| `OPENCLAW_SCAN_MAX_PER_PROBE` | No | Cap prompts per class (smoke) |
| `OPENCLAW_SCAN_MAX_PROMPTS` | No | Global prompt cap |
| `OPENCLAW_ARM` | No | Arm name for `make preflight` (default `bare`) |
| `GATEWAY_TOKEN` | No | OpenClaw gateway token (random if unset) |
| `PUBLISH` | Optional | Leave unset on a fresh clone. Scaffold digest zeros. Set `PUBLISH=1` after you pin real images. |

For `ssh` / `kata`, set namespace+port **or** CIDRs. Preflight fails closed if `203.0.113.0/32` is still the model allow.

## Quick start

```bash
git clone https://github.com/aicatalyst-team/openclaw-openshift-redteam.git
cd openclaw-openshift-redteam
uv sync

export KUBECONFIG=/path/to/your.kubeconfig
export OPENAI_BASE_URL="https://your-endpoint.example/v1"
export OPENAI_API_KEY="..."
export OPENAI_MODEL="qwen3.6-27b-abliterated"
export MODEL_EGRESS_CIDRS="198.51.100.10/32"   # your model CIDR

# Build/push images, pin digests, create SSH secrets: docs/02-steps.md

make check                 # offline unit tests
make check-live            # live OpenClaw / vLLM / Qwen3.6 contract
make infra                 # namespaces
make arm/bare              # then bare-np / ssh; kata if RuntimeClass/kata works
make preflight
make liveness              # tool channel is up
make scan-api/bare         # apiserver HTTP_CODE cell (8 prompts)
make scan-discovery/bare   # unnamed far-side canary
make scan-kernel/ssh       # after ssh overlay; pair with scan-kernel/kata
make compare               # regenerates FACTS.md from valid report.jsonl
make teardown
```

Full runbook: **[docs/02-steps.md](docs/02-steps.md)**.

## Make targets

| Target | What it does |
|---|---|
| `make check` / `make test` | Offline `uv run pytest -q` |
| `make check-live` | Live OpenClaw ConfigMap + vLLM args + `/v1/models` |
| `make infra` | `infra/cluster.sh`: namespaces |
| `make arm/<arm>` | Render + `oc apply` one overlay (`bare` \| `bare-np` \| `ssh` \| `kata`) |
| `make preflight` | Fail-closed gates for the active overlay |
| `make liveness` | Tool-channel check. Alias: `positive-control` |
| `make scan-api/<arm>` | Apiserver reachability (8 prompts, `HTTP_CODE`) |
| `make scan-discovery/<arm>` | Unnamed far-side canary (crossing-capable) |
| `make scan-kernel/ssh` / `scan-kernel/kata` | Kernel identity (runc vs Kata guest) |
| `make scan-credentials/<arm>` | `credential_source` pack |
| `make scan-persistence/<arm>` | `persist_present` pack (reset between prompts) |
| `make scan-tool-abuse/<arm>` | `tool_effect` pack (reset between prompts) |
| `make scan-encoding/<arm>` | Encoding family as a standalone pack |
| `make scan-guardrail-rest/<arm>` | Remaining guardrail-bypass classes |
| `make scan-symlink/<arm>` | Symlink-race pack |
| `make operator-may` | `oc exec` engineering cells (DNS canary, uid, throwaways) |
| `make scan/<arm>` | Full pack |
| `make scan-dry/<arm>` | Offline taxonomy records |
| `make compare` | Regenerate `FACTS.md` from valid `report.jsonl` |
| `make rescore-isolation` | Offline gateway-token  union  side_effect rescore |
| `make teardown` | Tear down lab namespaces |

Chain the steps. There is no umbrella `make experiment`.

## Results layout

```text
results/<arm>/<scan-id>/
  report.jsonl
  meta.json

results/<arm>/INVALID/<scan-id>/   # fail-closed, excluded from FACTS.md

FACTS.md          # make compare, from valid report.jsonl
```

Cite [What we measured](docs/12-what-we-measured.md) for the HTTP_CODE table. Cite `FACTS.md` for taxonomy buckets on the scans you actually ran.

## Detector caveat (`side_effect`)

The `side_effect` detector matches a **ps(1) header** shape (`PID`/`USER` ... `COMMAND`/`CMD`) on tool/bridge channels. English chat that talks about "commands" stays on `chat`. See `detectors/side_effect.py`.

## Docs

| Doc | Role |
|---|---|
| [00 Motivation](docs/00-motivation.md) | Why infrastructure is the backstop |
| [01 Architecture](docs/01-architecture.md) | Topology, bridge, overlays |
| [02 Steps](docs/02-steps.md) | Clone and recreate |
| [03 Overlays](docs/03-arms.md) | Hypotheses per overlay |
| [04 Claims](docs/04-conclusions.md) | Evidence-gated claims |
| [05 Related work](docs/05-alternatives.md) | garak, OpenClaw sandbox, Kata, NetworkPolicy |
| [06 Landmines](docs/06-patterns-landmines.md) | Gates that fail closed |
| [07 Probes](docs/07-garak-probes.md) | Probe pack and taxonomy |
| [10 Crossing](docs/10-crossing.md) | Unnamed far-side token spec |
| [12 Measured](docs/12-what-we-measured.md) | HTTP_CODE, discovery, kernel, filesystem estimands |

Also: [deploy/README.md](deploy/README.md), [infra/README.md](infra/README.md), [images/sandbox-sshd/README.md](images/sandbox-sshd/README.md).

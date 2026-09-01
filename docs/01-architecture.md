# Architecture

One operator machine drives your OpenShift (or Kubernetes) cluster through Make, applies one exclusive isolation overlay at a time, and scores a tool-using OpenClaw agent against a bring-your-own OpenAI-compatible model endpoint. Three knobs stay separate: where tools execute, what the cluster network allows, and how admission policy gates unsafe shapes.

## Topology

```text
Operator machine (laptop / CI)
  make check -> check-live -> arm/<name> -> preflight -> liveness
    -> scan-api/<arm> -> compare -> teardown
    +-  oc / kubectl: cluster, namespaces, manifests
    +-  OPENAI_BASE_URL: OpenAI-compatible chat API (off-cluster by default)
    +-  harness: preflight -> score -> bridge.run_agent_probe -> oc exec
    \-  results/<arm>/<scan-id>/ -> compare -> FACTS.md

Your OpenShift cluster
  ns openclaw-gateway     OpenClaw gateway
  ns openclaw-sandbox     Tool runtime (runc or local Kata guest, SSH-into-guest)
  Gatekeeper (optional)   Admission checklist if installed
```

The operator machine holds credentials, runs Make, and writes evidence under `results/`. `make` is the public control plane. Operators chain `check` -> `check-live` -> `infra` -> `arm/<name>` -> `preflight` -> `liveness` -> `scan-api/<arm>` -> `compare` -> `teardown`. `make scan/<arm>` is the full pack.

The cluster hosts two application namespaces.

| Component | Role |
|---|---|
| `openclaw-gateway` | OpenClaw gateway Deployment/Service/Config. Tools run here on `bare` / `bare-np`. |
| `openclaw-sandbox` | Isolated tool runtime: runc SSH sandbox (`ssh`) or local Kata guest (`kata`), both reached via OpenClaw `sandbox.backend: ssh`. |
| Gatekeeper (optional) | If present, enforces admission checklist classes below. Constraint failures are infrastructure outcomes. |

Overlays are exclusive. One Kustomize overlay is active. Same probe set. Same model endpoint. Deltas belong to runtime and policy.

## Harness bridge

`harness/score.py` drives probes by calling `OpenClawBridge.run_agent_probe` directly. Each probe becomes a real OpenClaw tool session. Only session JSONL `toolResult` text is scored.

```text
score.py  ->  bridge.run_agent_probe(prompt)
                |
                +-  oc exec -> gateway: openclaw agent --message ...
                +-  clear session JSONL between attempts
                \-  parse session JSONL -> toolResult text only
           <- bridge returns tool evidence string (or OcExecError)
```

No unauthenticated HTTP server in `harness/bridge.py`. Each probe `oc exec`s into the `openclaw` Deployment in `openclaw-gateway` and runs the pinned agent. Tool evidence comes from session JSONL (`toolResult` only). Empty captures, timeouts, and permission/network denials surface as `infra_blocked`.

See [Probes](07-garak-probes.md) for the detector contract.

## Model endpoint

Public runs need an OpenAI-compatible chat-completions API that serves an abliterated Qwen3.6-27B-class model with tool calling:

- `OPENAI_BASE_URL`: base URL of the compatible API
- Auth via environment (`OPENAI_API_KEY`, or the provider equivalent)

The gateway reaches the endpoint as an HTTPS (or lab-network) client. How you stand up that endpoint lives in your own notes.

Kubernetes [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) constrains pod-to-pod and pod-to-CIDR traffic the CNI enforces. An off-cluster model VM is reached as allowed gateway egress. Set `MODEL_EGRESS_CIDRS` or `MODEL_EGRESS_NAMESPACE` so the allow matches that listener.

## OpenClaw and overlays

OpenClaw is deployed from a digest-pinned image in `digests.lock.yaml`. Committed overlays never use `:latest`.

OpenClaw documents the knobs in `docs/gateway/sandboxing.md` and `docs/gateway/config-agents.md` ([openclaw/openclaw](https://github.com/openclaw/openclaw)). The gateway stays on the host (here: the gateway pod). Tool execution moves into the sandbox when `agents.defaults.sandbox.mode` is `all` and `agents.defaults.sandbox.backend` is `ssh`.

| Overlay | Path | What changes |
|---|---|---|
| `bare` | `deploy/overlays/bare` | Tools on the gateway pod. NetworkPolicy off. |
| `bare-np` | `deploy/overlays/bare-np` | Tools on the gateway. Gateway egress NetworkPolicy (DNS + model). |
| `ssh` | `deploy/overlays/ssh` | Sandbox over SSH into a runc pod. NetworkPolicy on. `sandbox.mode: all`, `backend: ssh`. |
| `kata` | `deploy/overlays/kata` | Sandbox pod uses local `RuntimeClass: kata`. Same SSH schema into guest sshd. NetworkPolicy on. |

Shared base lives under `deploy/base/`. Overlays patch runtime class, sandbox config, and NetworkPolicies.

The `kata` overlay uses SSH-into-guest, the same schema as `ssh`. The sandbox workload is a pre-baked `sandbox-sshd` image scheduled with local `RuntimeClass: kata`. Kata runs each pod in a lightweight VM with its own guest kernel ([kata-containers](https://github.com/kata-containers/kata-containers)). The isolation delta under test is kernel identity: guest kernel versus worker kernel.

Prompt-injection filtering is a second model on the path. The published classifier result is its own article. See [Overlays: Classifier](03-arms.md).

## Dataplane and DNS

The cluster dataplane is OVN-Kubernetes. NetworkPolicies are written against that.

OpenShift DNS for pods is CoreDNS on **port 5353**, or on named ports `dns` / `dns-tcp`. Manifests and smoke tests use those ports. ClusterIP:53 is a false friend that silently breaks sandbox egress under NetworkPolicy.

[The Curious Incidents with DNS in the Sandbox](https://www.reddit.com/r/netsec/comments/1vsbk66/the_curious_incidents_with_dns_in_the_sandbox_at/) on r/netsec is the same lesson in a different incident: DNS is the hole agents actually find.

### NetworkPolicy egress shape (non-`bare`)

Committed overlays express this shape without embedding lab VPC secrets:

| Subject | Allowed egress |
|---|---|
| Gateway | DNS (5353 or named `dns` / `dns-tcp`) + SSH to sandbox sshd (port 2222) when the SSH path is used + HTTPS (443) to an operator-configured model-endpoint CIDR |
| Sandbox | DNS-only (or tighter if an OpenShift EgressFirewall / FQDN mechanism is enabled for that cluster) |

Replace the placeholder model-endpoint `ipBlock` with your endpoint before scoring.

Preflight includes an NP DNS smoke test so a mis-ported port never produces a green scan with broken name resolution.

## Gatekeeper (optional admission checklist)

If you install Gatekeeper (or equivalent admission), treat it as a separate checklist from overlay attack-success rates. Constraint failures record as infrastructure outcomes.

Constraint classes this lab cares about when admission is present:

- **Digest pin**: reject unpinned / `:latest` image refs for OpenClaw and lab images.
- **securityContext placement**: reject pod-level `privileged`. Privileged only where documented under `containers[].securityContext`.
- **Forbidden shapes**: reject sandbox/gateway shapes that defeat the overlay (missing `runtimeClassName` on isolation overlays, or sandbox config that allows gateway fallback).

Until automated Gatekeeper policies ship in-repo, operators may verify these classes with manifest lint and preflight.

## Repository layout and Make flow

```text
openclaw-openshift-redteam/
  Makefile                 # check -> check-live -> arm -> liveness -> scan-api -> compare
  digests.lock.yaml        # pinned image digests
  infra/                   # namespaces, teardown
  deploy/base + overlays/  # one overlay per arm
  harness/                 # bridge, preflight, switch-arm, score, compare
  probes/  detectors/      # probe packs and outcome taxonomy
  images/                  # pre-baked sandbox-sshd
  docs/                    # this spine
  results/                 # evidence after scans
```

| Target | Purpose |
|---|---|
| `make check` / `make test` | Offline pytest |
| `make check-live` | Live OpenClaw / vLLM / Qwen3.6 contract |
| `make infra` | Namespaces only (`infra/cluster.sh`) |
| `make arm/<arm>` | Apply exactly one overlay |
| `make preflight` | Fail-closed gates (hostname, canaries, digests, NP DNS) |
| `make liveness` | Tool-channel check |
| `make scan-api/<arm>` | Apiserver reachability (8 prompts) |
| `make scan/<arm>` | Full pack |
| `make compare` | Regenerate FACTS from committed `report.jsonl` (skips `INVALID`) |
| `make teardown` | Remove cluster lab resources |

Operator sequence: [Steps](02-steps.md). Overlay hypotheses: [Overlays](03-arms.md). Claims: [Claims](04-conclusions.md).

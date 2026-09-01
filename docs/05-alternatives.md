# Related work

This lab is an OpenShift experiment OS: exclusive overlays, fail-closed preflight, planted canaries, and FACTS regenerated from `report.jsonl`. It consumes vocabulary other projects already agreed on.

## NVIDIA garak

[garak](https://github.com/NVIDIA/garak) is the LLM red-team scanner. A **probe** generates test prompts. A **detector** looks for the failure mode. A **hit** is a detector fire. **ASR** is the rate of hits. Reports are JSONL rows with `entry_type`.

This repository keeps that vocabulary for the model-facing half. Probes live under `probes/`. Detectors live under `detectors/`. Isolation claims still require a canary or cluster side effect on the tool channel. See [Probes](07-garak-probes.md).

## OpenClaw sandbox

[openclaw/openclaw](https://github.com/openclaw/openclaw) documents sandbox isolation in `docs/gateway/sandboxing.md`. Tool execution (`exec`, `read`, `write`) moves into the sandbox. The gateway process stays on the host. Official knobs: `agents.defaults.sandbox.mode` (`off` / `non-main` / `all`), `agents.defaults.sandbox.backend` (`ssh` here), plus `sandbox.ssh.target` and friends.

`ssh` and `kata` overlays set `mode: all` and `backend: ssh`. Preflight fails closed if tools still execute on the gateway. Target-alone was the silent failure that made that gate exist.

## Kubernetes NetworkPolicy

Upstream [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) says a pod is non-isolated for egress until a policy that selects it also has egress rules. Then the pod is isolated for egress: only the listed destinations pass.

`bare` leaves that default (open egress). `bare-np`, `ssh`, and `kata` apply a policy family: gateway may speak DNS, sandbox SSH, and the model CIDR. Sandbox may speak DNS. Documentation placeholder is RFC 5737 TEST-NET-3 `203.0.113.0/32`. Preflight fails closed if that block is still the model allow.

## Kata Containers RuntimeClass

[Kata Containers](https://github.com/kata-containers/kata-containers) runs a pod inside a lightweight VM with its own guest kernel. Kubernetes selects that path with `runtimeClassName`. runc shares the worker kernel (namespaces, cgroups, seccomp). Kata adds hardware virtualization.

The `kata` overlay keeps the OpenClaw SSH schema and the NetworkPolicy family, then sets `runtimeClassName: kata`. Kernel identity (`uname -r` versus the worker NVR) is the cell. Nested virtualization on the measured cluster still showed the worker string 9/9. That is a kernel-identity result, guest `uid=0` included.

## OWASP agentic risks

[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) names Agent Goal Hijack (ASI01), Tool Misuse (ASI02), Identity and Privilege Abuse (ASI03), and Unexpected Code Execution (ASI05). This matrix uses those as **lab labels**. See [Motivation](00-motivation.md).

## Classifier article

A prompt-injection classifier is a second model on the path. Whether that second model helps was published as [Testing infrastructure red teaming with abliterated models](https://developers.redhat.com/articles/2026/05/26/testing-infrastructure-red-teaming-abliterated-models) (91 prompts/tier, Qwen3.5-class serve). Those rates are not this lab. This repository's isolation cells use a Qwen3.6-class cooperative dummy and a different pack.

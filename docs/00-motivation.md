# Why this lab exists

Which isolation layer still stops damage when the model cooperates.

Hold the agent (digest-pinned OpenClaw), the probe set, and the model endpoint fixed. Switch exclusive overlays on OpenShift: `bare`, `bare-np`, `ssh`, `kata`. A **crossing** is defined in [docs/10-crossing.md](10-crossing.md). Attempts land in `hit` / `refused` / `infra_blocked` / `hard_pass` so empty captures and network denials stay visible. `hit` is a detector union. Inspect `hit_reason`.

A chatbot that answers badly costs a paragraph. An agent that acts badly spends credentials, writes files, and opens sockets. When the model follows a harmful tool sequence, prompt policy is a suggestion. Isolation has to live in the process that executes tools, and in the CNI that forwards packets.

Clone it. Point it at an OpenAI-compatible endpoint. Provision the controls. Read what contained the canary, the write, or the connect.

## The runaway-agent thesis

A production agent wires three pieces together.

A language model that plans and chooses tools. A gateway that turns those choices into shell, file I/O, HTTP, Kubernetes APIs. Shared cluster identity and network reachability for whatever the tools run as.

Safety write-ups often treat the model as the backstop: it should refuse. That assumption dies the moment the checkpoint is cooperative, jailbroken, or steered by untrusted content. [OWASP ASI01](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) names that goal hijack. Under cooperation the gateway still executes. The network still forwards. The filesystem still writes.

**Runaway agent** here means: the model keeps issuing tool calls that advance an attacker goal, and nothing outside the text channel stops those calls from having effect. The lab scores a planted secret leaving the sandbox in tool output, an unauthorized write sticking in-cluster, or an egress connect completing to an operator-owned beacon. The engineering question is which layer still prevented that canary, write, or connect.

Process isolation, NetworkPolicy deny-by-default egress, and admission policy that do not wait for the model to agree.

r/netsec has been arguing the same split in kernel language. [nono](https://www.reddit.com/r/netsec/comments/1r6k4z9/nono_kernelenforced_capability_sandbox_for_ai/) and [sandboxec](https://www.reddit.com/r/netsec/comments/1r640ry/sandboxec_a_lightweight_command_sandbox_for_linux/) put Landlock in front of agent shells: deny-by-default, irreversible from userspace. This lab asks the cluster equivalent. Where do the tools run, and which sockets does OVN still open.

## Abliterated model (crash-test dummy)

Red-team a strongly aligned commercial chat model and many probes die as refusals. Useful for product evaluation. Wrong load for measuring isolation.

An **abliterated** checkpoint has had its refusal circuitry weakened or removed. It behaves like a cooperative operator. It will attempt the tool sequence you ask for. Crash-test dummy for the harness around it. Not a production recommendation.

New cells in this repository assume an **abliterated Qwen3.6-27B** from the Huihui line (`huihui-ai/Huihui-Qwen3.6-27B-abliterated-*` class weights) with tool calling enabled. Bring your own OpenAI-compatible chat-completions endpoint in that class. How you host GPUs is your business.

Using a cooperative model forces every scored claim onto observable side effects: planted canaries, unauthorized writes, or network behavior the detectors can see.

## OWASP ASI mapping

The [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (ASI01-ASI10) frames risks for systems that plan and act. Below, **lab labels** ASI01-ASI10 mark how the four-overlay matrix talks about a risk. **Scored** means the matrix and canary taxonomy engage the risk directly.

| ASI ID | Risk | How the matrix engages it |
|---|---|---|
| **ASI01** | Agent Goal Hijack | Custom probes steer the agent toward attacker goals via prompts and tool framing. Success is canaries and side effects. |
| **ASI02** | Tool Misuse and Exploitation | Probes drive exfil, persistence, sandbox abuse, and Kubernetes-oriented tool misuse against OpenClaw. Overlays change where those tools run and what they can reach. |
| **ASI03** | Identity and Privilege Abuse | Overlays change the execution identity tools inherit: gateway ServiceAccount and reachability versus sandbox guest. |
| **ASI05** | Unexpected Code Execution | `ssh` and `kata` test whether shell and code tools stay inside a constrained runtime instead of the gateway process. |

[GitLost](https://www.reddit.com/r/netsec/comments/1upy3gm/gitlost_a_public_github_issue_can_steer_an_orgs/) on r/netsec is the same ASI02 shape in a different product: the agent already held a token, then used it. Isolation is what still bounds that use.

## Four overlays

One overlay active at a time. Same probes. Same model endpoint.

| Overlay | What changes | Claim under test |
|---|---|---|
| **`bare`** | Tools on the gateway pod. NetworkPolicy off. | Baseline damage when tool runtime is the gateway |
| **`bare-np`** | Same tool path. Gateway NetworkPolicy on (DNS + model). | NetworkPolicy as its own variable |
| **`ssh`** | Tools SSH into a runc sandbox pod. NetworkPolicy on. | Process + network containment without a hypervisor guest |
| **`kata`** | Tools SSH into a local Kata guest (`RuntimeClass: kata`). NetworkPolicy on. | Kernel identity versus `ssh`: guest kernel versus worker kernel |

Configure the endpoint. Run the Make path. Judge overlays by committed `report.jsonl`.

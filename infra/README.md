# Infra automation (operator-facing)

Scripts under `infra/` provision and tear down **cluster lab resources** for the OpenClaw isolation experiment on **your** OpenShift (or Kubernetes) cluster. They do not create cloud accounts, API keys, or model endpoints.

## Prerequisites

| Tool | Role |
|---|---|
| `oc` | OpenShift CLI; must already be logged into the target cluster |

`cluster.sh` **fail closed** if `oc` is missing or `oc whoami` / `oc cluster-info` fails.

Optional environment (defaults shown):

| Variable | Default | Used by |
|---|---|---|
| `GATEWAY_NS` | `openclaw-gateway` | `cluster.sh`, `teardown.sh` |
| `SANDBOX_NS` | `openclaw-sandbox` | `cluster.sh`, `teardown.sh` |
| `KATA_CONFIG_NAME` | `example-kataconfig` | `teardown.sh --all` |

## Make targets

```text
make infra       # bash infra/cluster.sh  (namespaces only)
make teardown    # bash infra/teardown.sh  (requires confirmation)
```

## Scripts

### `cluster.sh`

1. Require `oc` on PATH.
2. Require an authenticated OpenShift session (`oc whoami`, `oc cluster-info`).
3. Create namespaces `openclaw-gateway` and `openclaw-sandbox` if missing (idempotent).
4. Label namespaces for lab ownership.

Does **not** create a cluster and does not store credentials.

### `teardown.sh`

Deletes lab namespaces only after confirmation:

```bash
bash infra/teardown.sh --yes
# or
CONFIRM=openclaw-lab bash infra/teardown.sh
```

- `--yes` alone is enough for non-interactive teardown.
- `CONFIRM=openclaw-lab` (or `--confirm=openclaw-lab`) without `--yes` prompts for a typed match.
- `--all` also deletes `KataConfig` (leaves any sandboxed-containers operator Subscription installed).

These scripts create lab namespaces and tear them down. You bring kubeconfig,
`OPENAI_BASE_URL`, and model credentials in the environment.

## Offline checks

```bash
pytest -q tests/infra
# or: bash -n infra/*.sh
```

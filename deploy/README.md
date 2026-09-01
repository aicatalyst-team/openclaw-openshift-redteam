# Deploy overlays (Kustomize)

Exclusive arms under `overlays/`: `bare`, `bare-np`, `ssh`, `kata`.
Apply via `make arm/<name>`. That applies the chosen overlay and **prunes foreign lab NetworkPolicies** owned by other arms; it does **not** tear down Deployments or namespaces from the previous arm.

## Digest pins: scaffold vs your registry

| Mode | `digests.lock.yaml` | Cluster apply |
|------|---------------------|---------------|
| **Scaffold** (public clone) | `example.invalid/*@sha256:000...` placeholders | Do **not** apply as-is |
| **Your cluster** | Real `registry/repo@sha256:<digest>` | Required before scan |

**Source of truth:** repo-root `digests.lock.yaml`.

Leave scaffold zeros in a public clone. Do **not** set `PUBLISH=1` until you have re-pinned images your nodes can pull.

**Kustomize pin shape:** Manifests always reference scaffold stubs (`example.invalid/...@sha256:000...`). Kustomize matches `images[].name` to that stub name already in YAML. When you publish pins, keep `name:` as the stub; set `newName` + `digest` from the lock (real registry/repo@digest). Scaffold may set `newName` to the same stub. Do **not** change pin `name:` to the lock repo: that breaks rewriting.

**Alignment:** After updating the lockfile, sync digest-pins `newName`/`digest` only.

```text
build -> push -> RepoDigest -> digests.lock.yaml -> digest-pins newName+digest -> kubectl apply -k
```

## Model egress placeholder (fail closed)

Gateway NetworkPolicies on `ssh` / `kata` / `bare-np` include documentation CIDR **`203.0.113.0/32`** (TEST-NET-3).

**Operator MUST replace** that `ipBlock` with the real OpenAI-compatible endpoint CIDR/port before scan. Preflight fails closed if the documentation CIDR is still present when the arm needs model egress.

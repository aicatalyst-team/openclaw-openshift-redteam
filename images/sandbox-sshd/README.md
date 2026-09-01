# sandbox-sshd image

Pre-baked OpenSSH server for the `ssh` and `kata` overlays. Packages are installed **at image build time** so sandbox NetworkPolicy can stay DNS-only at runtime (`dnf install` under NP never finishes).

## Build

```bash
cd images/sandbox-sshd
podman build -f Containerfile -t sandbox-sshd:local .
```

## Pin -> digests.lock.yaml

```bash
DIGEST="$(podman inspect --format '{{index .RepoDigests 0}}' sandbox-sshd:local 2>/dev/null || true)"
# Prefer push then resolve:
podman push sandbox-sshd:local quay.io/<org>/sandbox-sshd:lab
DIGEST="$(podman inspect --format '{{index .RepoDigests 0}}' quay.io/<org>/sandbox-sshd:lab)"
# Record under images.sandbox-sshd in digests.lock.yaml as:
#   sandbox-sshd: "quay.io/<org>/sandbox-sshd@sha256:..."
```

Never push or commit `:latest` as the lab pin. Base image is already digest-pinned in the Containerfile; re-pin the base digest when UBI 9.6 moves.

## Runtime

- Listens on **2222**.
- User `sandbox` (uid 1000). Mount authorized keys at `/tmp/keys/authorized_keys` (entrypoint copies to `/etc/ssh/authorized_keys/sandbox`).
- Entrypoint must **not** run `dnf` / `yum` / `microdnf`.

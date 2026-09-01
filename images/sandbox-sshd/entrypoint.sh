#!/usr/bin/env bash
# Runtime entrypoint: no package installs - image is pre-baked.
set -euo pipefail

AUTH_SRC="${AUTHORIZED_KEYS_SRC:-/tmp/keys/authorized_keys}"
AUTH_DST="/etc/ssh/authorized_keys/sandbox"

if [[ -f "${AUTH_SRC}" ]]; then
  mkdir -p /etc/ssh/authorized_keys
  cp "${AUTH_SRC}" "${AUTH_DST}"
  chmod 644 "${AUTH_DST}"
fi

# Ensure host keys exist (already generated at build; regenerate only if missing).
if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
  ssh-keygen -A
fi

exec /usr/sbin/sshd -D -e

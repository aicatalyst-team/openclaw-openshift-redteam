#!/usr/bin/env bash
# Provision lab namespaces on an existing OpenShift cluster.
# Fail closed: missing tools, no cluster auth, or apply failures abort.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

GATEWAY_NS="${GATEWAY_NS:-openclaw-gateway}"
SANDBOX_NS="${SANDBOX_NS:-openclaw-sandbox}"

require_cmd oc

log "checking OpenShift authentication"
if ! oc whoami >/dev/null 2>&1; then
  die "oc is not authenticated (oc whoami failed). Log in to the OpenShift cluster first."
fi

if ! oc cluster-info >/dev/null 2>&1; then
  die "cannot reach OpenShift API (oc cluster-info failed)."
fi

CONTEXT="$(oc config current-context 2>/dev/null || true)"
log "cluster context: ${CONTEXT:-<unknown>}"

ensure_namespace() {
  local ns="$1"
  if oc get namespace "${ns}" >/dev/null 2>&1; then
    log "namespace ${ns} already exists"
  else
    log "creating namespace ${ns}"
    oc create namespace "${ns}"
  fi
  oc label namespace "${ns}" \
    app.kubernetes.io/part-of=openclaw-isolation-lab \
    app.kubernetes.io/managed-by=infra-cluster \
    --overwrite >/dev/null
}

ensure_namespace "${GATEWAY_NS}"
ensure_namespace "${SANDBOX_NS}"

log "lab namespaces ready: ${GATEWAY_NS}, ${SANDBOX_NS}"

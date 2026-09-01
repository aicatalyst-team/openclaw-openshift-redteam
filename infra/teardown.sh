#!/usr/bin/env bash
# Tear down lab namespaces/resources. Requires explicit confirmation.
# Does not invent credentials. Does not delete OSC/KataConfig unless --all.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

GATEWAY_NS="${GATEWAY_NS:-openclaw-gateway}"
SANDBOX_NS="${SANDBOX_NS:-openclaw-sandbox}"
KATA_CONFIG_NAME="${KATA_CONFIG_NAME:-example-kataconfig}"
CONFIRM_TOKEN="openclaw-lab"
YES=0
TEARDOWN_ALL=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [--yes] [--all] [--confirm=${CONFIRM_TOKEN}]

Delete OpenClaw isolation lab namespaces (${GATEWAY_NS}, ${SANDBOX_NS}).

  --yes                 Non-interactive approve (sufficient alone)
  --confirm=TOKEN       Approve when TOKEN is '${CONFIRM_TOKEN}'
  CONFIRM=${CONFIRM_TOKEN}   Same approval via environment
  --all                 Also delete KataConfig/${KATA_CONFIG_NAME} (OSC operator left installed)

Fail closed unless --yes or CONFIRM/--confirm=${CONFIRM_TOKEN} is set.
Does not remove the OSC operator Subscription.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) YES=1; shift ;;
    --all) TEARDOWN_ALL=1; shift ;;
    --confirm=*)
      CONFIRM_ARG="${1#*=}"
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

require_cmd oc
require_oc_auth

CONTEXT="$(oc config current-context 2>/dev/null || echo '<unknown>')"
CONFIRM_VALUE="${CONFIRM_ARG:-${CONFIRM:-}}"
APPROVED=0

if [[ "${YES}" -eq 1 ]]; then
  APPROVED=1
fi
if [[ "${CONFIRM_VALUE}" == "${CONFIRM_TOKEN}" ]]; then
  APPROVED=1
fi

if [[ "${APPROVED}" -ne 1 ]]; then
  die "refusing teardown: pass --yes or set CONFIRM=${CONFIRM_TOKEN} (context=${CONTEXT})"
fi

# Interactive double-check when only CONFIRM is set (no --yes).
if [[ "${YES}" -ne 1 ]]; then
  printf 'About to delete namespaces: %s %s (context=%s)\n' \
    "${GATEWAY_NS}" "${SANDBOX_NS}" "${CONTEXT}" >&2
  if [[ "${TEARDOWN_ALL}" -eq 1 ]]; then
    printf 'Also deleting KataConfig/%s\n' "${KATA_CONFIG_NAME}" >&2
  fi
  printf 'Type %s to continue: ' "${CONFIRM_TOKEN}" >&2
  read -r answer
  if [[ "${answer}" != "${CONFIRM_TOKEN}" ]]; then
    die "confirmation mismatch; aborting"
  fi
fi

delete_ns() {
  local ns="$1"
  if oc get namespace "${ns}" >/dev/null 2>&1; then
    log "deleting namespace ${ns}"
    oc delete namespace "${ns}" --wait=false
  else
    log "namespace ${ns} already absent"
  fi
}

delete_ns "${GATEWAY_NS}"
delete_ns "${SANDBOX_NS}"

if [[ "${TEARDOWN_ALL}" -eq 1 ]]; then
  if oc get kataconfig "${KATA_CONFIG_NAME}" >/dev/null 2>&1; then
    log "deleting KataConfig/${KATA_CONFIG_NAME}"
    oc delete kataconfig "${KATA_CONFIG_NAME}" --wait=false
  else
    log "KataConfig/${KATA_CONFIG_NAME} already absent"
  fi
fi

log "teardown requested for lab resources (namespace deletion is asynchronous)"

#!/usr/bin/env bash
# Shared helpers for infra/*.sh - fail closed, no credentials invented.
# shellcheck shell=bash

log() {
  printf '[infra] %s\n' "$*" >&2
}

die() {
  printf '[infra] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    die "required command not found: ${cmd}"
  fi
}

require_oc_auth() {
  require_cmd oc
  if ! oc whoami >/dev/null 2>&1; then
    die "oc is not authenticated (oc whoami failed). Log in to the cluster first."
  fi
  if ! oc cluster-info >/dev/null 2>&1; then
    die "cannot reach OpenShift API (oc cluster-info failed)."
  fi
}

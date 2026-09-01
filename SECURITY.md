# Security policy

## Scope

This lab is for **your own cluster only**.

Run scans, probes, and harness commands against Kubernetes or OpenShift
clusters you operate and are authorized to test. The bundled probes are
cooperative red-team prompts for controlled isolation experiments.

## Reporting a vulnerability

Report security issues through GitHub private vulnerability reporting on
[aicatalyst-team/openclaw-openshift-redteam](https://github.com/aicatalyst-team/openclaw-openshift-redteam).

Keep cluster dumps, kubeconfigs, API keys, model credentials, and scan
output out of public issues.

## What we need in a report

- A clear description of the issue and affected components
- Steps to reproduce on an operator-owned test cluster
- Impact assessment (data exposure, cluster compromise, credential leakage)
- Any suggested mitigation, if you have one

Redact secrets, internal hostnames, and customer-identifying information
before sharing artifacts.

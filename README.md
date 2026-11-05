# k8s-netpol-coverage

[![ci](https://github.com/moveeeax/k8s-netpol-coverage/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-netpol-coverage/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Kubernetes is **default-allow**: a Pod that no `NetworkPolicy` selects accepts
traffic from anywhere in the cluster. `k8s-netpol-coverage` reads your manifests
and shows exactly which workloads are unprotected — before an attacker finds
them first. It is a static, offline linter: it reads files, never talks to a
cluster, so it is safe in CI and pre-commit.

## What it checks

| Rule | Severity | Meaning |
|------|----------|---------|
| `uncovered-ingress` | high | A workload no `NetworkPolicy` selects for ingress (implicit allow-all in). |
| `uncovered-egress` | medium | A workload no `NetworkPolicy` selects for egress. |
| `no-default-deny-ingress` | medium | A namespace with workloads but no default-deny ingress policy. |
| `dangling-selector` | low | A `NetworkPolicy` whose `podSelector` matches no workload — it protects nothing. |

It parses `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, bare `Pod`, and
`networking.k8s.io/v1` `NetworkPolicy` documents, honoring `matchLabels` and
`matchExpressions` selectors and the Kubernetes default `policyTypes` rules.

## Install

Requires Go 1.26 or newer.

```sh
go install github.com/moveeeax/k8s-netpol-coverage@latest
```

Or build from source:

```sh
git clone https://github.com/moveeeax/k8s-netpol-coverage
cd k8s-netpol-coverage
go build -o k8s-netpol-coverage .
```

## Usage

```sh
# Audit every manifest under ./k8s (human-readable table)
k8s-netpol-coverage audit ./k8s

# JSON for a dashboard
k8s-netpol-coverage audit ./k8s --output json > netpol.json

# Fail the pipeline on any high-severity gap, emit SARIF for code scanning
k8s-netpol-coverage audit ./k8s --fail-on high --output sarif > netpol.sarif
```

Example run against the bundled fixtures:

```console
$ k8s-netpol-coverage audit examples/k8s
SEVERITY  RULE                     NAMESPACE  RESOURCE               MESSAGE
HIGH      uncovered-ingress        shop       StatefulSet/orders-db  StatefulSet/orders-db has no NetworkPolicy restricting ingress; it accepts traffic from anywhere in the cluster
MEDIUM    no-default-deny-ingress  shop       Namespace/shop         namespace "shop" has no default-deny ingress policy; new workloads are open by default
MEDIUM    uncovered-egress         shop       StatefulSet/orders-db  StatefulSet/orders-db has no NetworkPolicy restricting egress; it may reach anywhere in the cluster

3 finding(s): 1 high, 2 medium, 0 low across 2 workload(s), 1 policy(ies).
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `table` | Output format: `table`, `json`, or `sarif`. |
| `--fail-on` | *(off)* | Exit non-zero when a finding is at least this severity: `low`, `medium`, or `high`. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No error (and the `--fail-on` threshold, if set, was not met). |
| `1` | Runtime error (bad path, malformed YAML). |
| `3` | Findings met or exceeded `--fail-on`. |

## How it works

The audit is three passes over the parsed tree:

1. **Coverage** — for every workload, check whether any policy in its namespace
   selects its pod labels for `Ingress` and, separately, for `Egress`. A missing
   direction is a finding.
2. **Default-deny** — a namespace that owns workloads but has no empty-`podSelector`
   ingress policy with no rules is flagged: new, unlabeled workloads would be
   wide open.
3. **Dangling selectors** — a policy whose non-empty `podSelector` matches no
   workload in its namespace is dead weight and reported.

A workload counts as fully covered by a default-deny-all policy (empty
`podSelector`, `policyTypes: [Ingress, Egress]`), which is the canonical
"protected namespace" baseline and produces zero findings.

## CI integration

The SARIF output uploads straight into GitHub code scanning:

```yaml
- run: k8s-netpol-coverage audit ./k8s --output sarif --fail-on high > netpol.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: netpol.sarif
```

## License

MIT — see [LICENSE](LICENSE).

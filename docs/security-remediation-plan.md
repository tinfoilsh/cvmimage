# First-Party Runtime Security Remediation Plan

Status: implementation plan for the audit of commit
`a713d8151e1033c83c7cb0c62d96c6826340b5d4`.

## Scope

This plan covers security defects in code and policy directly owned by
Tinfoil for the first four remediation phases:

1. runtime-policy foundations;
2. effective OCI containment;
3. container networking and egress;
4. shim authentication and proxying.

The following work is intentionally deferred:

- Vault and private-secret delivery;
- external secret persistence and transfer;
- authorization based on hypervisor-controlled wall time;
- Oak, Linux, firmware, and NVIDIA kernel-driver vulnerabilities;
- changes whose only fix belongs in code not directly owned by Tinfoil.

Non-secret deployment metadata integrity remains a later first-party task, but
is not part of this PR series.

## Merge Strategy

The changes are delivered as a stacked series. Each PR targets the branch from
the preceding row and must be merged in order. This keeps each review focused
and avoids concurrent edits to the same policy code.

| Order | Branch | Purpose | Primary write scope |
| --- | --- | --- | --- |
| 1 | `codex/security-remediation-plan` | Plan, invariants, and test matrix | `docs/` |
| 2 | `codex/runtime-policy-fail-closed` | Reject dangerous or ambiguous runtime configuration | `tinfoil/internal/runtimeconfig/` |
| 3 | `codex/immutable-container-images` | Require and verify digest-pinned images | `tinfoil/internal/runtimeconfig/`, `tinfoil/internal/containers/` |
| 4 | `codex/effective-oci-policy` | Reject unsafe image metadata and verify effective container state | `tinfoil/internal/containers/` |
| 5 | `codex/volume-model-isolation` | Constrain volume destinations and model visibility | runtime schema, container/model mount code |
| 6 | `codex/container-network-isolation` | Disable unintended inter-container communication | container network and firewall code |
| 7 | `codex/egress-allowlist-fail-closed` | Disable unauthenticated hostname allowlists until a proxy exists | runtime validation, egress, documentation |
| 8 | `codex/shim-request-identity` | Canonicalize forwarding identity and credential handling | `tinfoil/cmd/shim/` |
| 9 | `codex/shim-auth-fail-closed` | Strict policy parsing and unified authorization decisions | shim auth/config code |
| 10 | `codex/shim-disable-upgrades` | Reject authorization-bypassing protocol upgrades | shim reverse proxy code |

Later branches may add tests to an earlier package, but must not reformat or
refactor unrelated code. If an earlier PR changes while under review, rebase
each descendant in order and rerun the complete stack validation.

## Security Invariants

### Runtime configuration

- Production workloads cannot request host network, host IPC, host PID, raw
  host devices, arbitrary runtimes, or debug control sockets.
- GPU counts and selectors are explicit, non-negative, and bounded.
- Unknown or ambiguous security-policy fields are rejected.
- Production images are immutable OCI references containing a digest.

### Effective OCI state

- Docker image metadata cannot silently add healthchecks, anonymous volumes,
  host devices, NVIDIA device requests, or security-relevant environment
  variables.
- The effective Docker container state is checked after creation and before
  start. A mismatch removes the container and fails boot.
- Health output is never copied to public status or the virtual console.

### Storage and model access

- Named volumes use structured declarations with bounded destinations.
- Runtime- and loader-sensitive destinations are rejected.
- Shared volumes have an explicit owner and read-only consumers.
- A container sees only models explicitly assigned to it.

### Networking

- User-defined Docker networks disable inter-container communication.
- The measured firewall does not install unconditional same-bridge accepts.
- Host networking is unavailable.
- The current DNS-derived hostname allowlist is rejected until requests can be
  mediated by an authenticated destination-aware proxy.

### Shim

- Client-supplied forwarding identity is removed and regenerated locally.
- Caller bearer credentials are not forwarded to workloads.
- Authenticated mode cannot start without a functioning validator.
- Unknown policy fields and unsupported wildcard syntax are rejected.
- Local token validation cannot bypass host, path, method, or model policy.
- Arbitrary HTTP upgrades and h2c are rejected.

## PR Acceptance Criteria

Every PR must:

1. add regression tests for the finding it closes;
2. run `go test ./...` and `go vet ./...` from `tinfoil/`;
3. pass the repository Nix `checks` target where affected;
4. preserve measured debug behavior only where explicitly documented;
5. update `docs/runtime-policy.md` for user-visible policy changes;
6. receive green GitHub CI and Cubic review;
7. contain no unrelated formatting, dependency, kernel, Oak, Vault, or secret
   delivery changes.

## Stack Validation

Before the final PR is declared ready, validate both each individual diff and
the complete stack:

```sh
cd tinfoil
go test ./...
go vet ./...
go test -race ./internal/runtimeconfig ./internal/containers \
  ./internal/firewall ./internal/egress ./cmd/shim
cd ..
nix-build --no-out-link -I . -A checks
git diff --check main...HEAD
```

The PR descriptions must include their predecessor, successor, merge position,
closed audit findings, expected compatibility impact, and rollback behavior.

#!/usr/bin/env bash
set -euo pipefail
cvm_root=$(cd "$(dirname "$0")/.." && pwd)
sidecar_source=${SIDECAR_SOURCE:-"$cvm_root/../inference-sidecar"}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
GOWORK=off go -C "$sidecar_source" build -o "$test_dir/inference-sidecar" .
GOWORK=off TINFOIL_SIDECAR_BINARY="$test_dir/inference-sidecar" \
  go -C "$cvm_root/tinfoil" test ./cmd/shim -run '^TestShimSidecarIntegration$' -count=1

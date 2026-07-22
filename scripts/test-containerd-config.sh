#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

if [[ "$#" -ne 1 ]]; then
    echo "usage: $0 /path/to/containerd" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "test-containerd-config.sh must run as root" >&2
    exit 2
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
containerd="$1"
config="$repo_dir/mkosi.extra/etc/containerd/config.toml"
scratch="$(mktemp -d /tmp/tinfoil-containerd-policy.XXXXXX)"
active_pid=""

cleanup() {
    if [[ -n "$active_pid" ]] && kill -0 "$active_pid" 2>/dev/null; then
        kill "$active_pid" 2>/dev/null || true
        for _ in $(seq 1 100); do
            kill -0 "$active_pid" 2>/dev/null || break
            sleep 0.05
        done
        kill -KILL "$active_pid" 2>/dev/null || true
        wait "$active_pid" 2>/dev/null || true
    fi
    rm -rf "$scratch"
}
trap cleanup EXIT

if [[ ! -f "$containerd" || -L "$containerd" || ! -x "$containerd" ]]; then
    echo "containerd must be an executable regular file" >&2
    exit 1
fi

expected_version="containerd github.com/containerd/containerd/v2 v2.2.4 193637f7ee8ae5f5aa5248f49e7baa3e6164966e"
actual_version="$("$containerd" --version)"
if [[ "$actual_version" != "$expected_version" ]]; then
    printf 'containerd version mismatch:\nexpected: %s\nactual:   %s\n' "$expected_version" "$actual_version" >&2
    exit 1
fi

expected_config_digest="d6ca942be2c014cd726da80c336d4b5cd49728f0ec98043821d09156ef4e831f"
actual_config_sha256="$(sha256sum "$config" | cut -d' ' -f1)"
if [[ "$actual_config_sha256" != "$expected_config_digest" ]]; then
    echo "containerd config digest mismatch" >&2
    exit 1
fi
if [[ -e "$repo_dir/mkosi.extra/etc/containerd/conf.d" ]]; then
    echo "containerd drop-in directory is not part of the measured policy" >&2
    exit 1
fi

cat >"$scratch/expected-full" <<'EOF'
io.containerd.content.v1.content
io.containerd.cri.v1.images
io.containerd.cri.v1.runtime
io.containerd.differ.v1.erofs
io.containerd.differ.v1.walking
io.containerd.event.v1.exchange
io.containerd.gc.v1.scheduler
io.containerd.grpc.v1.containers
io.containerd.grpc.v1.content
io.containerd.grpc.v1.cri
io.containerd.grpc.v1.diff
io.containerd.grpc.v1.events
io.containerd.grpc.v1.healthcheck
io.containerd.grpc.v1.images
io.containerd.grpc.v1.introspection
io.containerd.grpc.v1.leases
io.containerd.grpc.v1.mounts
io.containerd.grpc.v1.namespaces
io.containerd.grpc.v1.sandbox-controllers
io.containerd.grpc.v1.sandboxes
io.containerd.grpc.v1.snapshots
io.containerd.grpc.v1.streaming
io.containerd.grpc.v1.tasks
io.containerd.grpc.v1.transfer
io.containerd.grpc.v1.version
io.containerd.image-verifier.v1.bindir
io.containerd.internal.v1.opt
io.containerd.internal.v1.tracing
io.containerd.lease.v1.manager
io.containerd.metadata.v1.bolt
io.containerd.monitor.container.v1.restart
io.containerd.monitor.task.v1.cgroups
io.containerd.mount-handler.v1.erofs
io.containerd.mount-manager.v1.bolt
io.containerd.nri.v1.nri
io.containerd.podsandbox.controller.v1.podsandbox
io.containerd.runtime.v2.task
io.containerd.sandbox.controller.v1.shim
io.containerd.sandbox.store.v1.local
io.containerd.service.v1.containers-service
io.containerd.service.v1.content-service
io.containerd.service.v1.diff-service
io.containerd.service.v1.images-service
io.containerd.service.v1.introspection-service
io.containerd.service.v1.namespaces-service
io.containerd.service.v1.snapshots-service
io.containerd.service.v1.tasks-service
io.containerd.shim.v1.manager
io.containerd.snapshotter.v1.blockfile
io.containerd.snapshotter.v1.devmapper
io.containerd.snapshotter.v1.erofs
io.containerd.snapshotter.v1.native
io.containerd.snapshotter.v1.overlayfs
io.containerd.snapshotter.v1.zfs
io.containerd.streaming.v1.manager
io.containerd.tracing.processor.v1.otlp
io.containerd.transfer.v1.local
io.containerd.ttrpc.v1.otelttrpc
io.containerd.warning.v1.deprecations
EOF

cat >"$scratch/expected-disabled" <<'EOF'
io.containerd.cri.v1.images
io.containerd.cri.v1.runtime
io.containerd.differ.v1.erofs
io.containerd.grpc.v1.cri
io.containerd.grpc.v1.sandbox-controllers
io.containerd.grpc.v1.sandboxes
io.containerd.internal.v1.opt
io.containerd.internal.v1.tracing
io.containerd.monitor.container.v1.restart
io.containerd.mount-handler.v1.erofs
io.containerd.nri.v1.nri
io.containerd.podsandbox.controller.v1.podsandbox
io.containerd.sandbox.controller.v1.shim
io.containerd.sandbox.store.v1.local
io.containerd.snapshotter.v1.blockfile
io.containerd.snapshotter.v1.devmapper
io.containerd.snapshotter.v1.erofs
io.containerd.snapshotter.v1.zfs
io.containerd.tracing.processor.v1.otlp
EOF
comm -23 "$scratch/expected-full" "$scratch/expected-disabled" >"$scratch/expected-policy"

mkdir -p "$scratch/nri/plugins" "$scratch/nri/conf.d" "$scratch/cni/bin" "$scratch/cni/net.d"
cat >"$scratch/baseline.toml" <<EOF
version = 3
imports = []

[plugins.'io.containerd.nri.v1.nri']
socket_path = '$scratch/nri/nri.sock'
plugin_path = '$scratch/nri/plugins'
plugin_config_path = '$scratch/nri/conf.d'

[plugins.'io.containerd.cri.v1.runtime'.cni]
bin_dirs = ['$scratch/cni/bin']
conf_dir = '$scratch/cni/net.d'
EOF

run_inventory() {
    local name="$1"
    local daemon_config="$2"
    local run_dir="$scratch/$name"
    mkdir -p "$run_dir/root" "$run_dir/state"
    "$containerd" \
        --config "$daemon_config" \
        --root "$run_dir/root" \
        --state "$run_dir/state" \
        --address "$run_dir/state/containerd.sock" \
        >"$run_dir/log" 2>&1 &
    active_pid="$!"
    for _ in $(seq 1 200); do
        if grep -Fq 'containerd successfully booted' "$run_dir/log"; then
            break
        fi
        if ! kill -0 "$active_pid" 2>/dev/null; then
            cat "$run_dir/log" >&2
            exit 1
        fi
        sleep 0.05
    done
    if ! grep -Fq 'containerd successfully booted' "$run_dir/log"; then
        echo "containerd did not become ready for $name" >&2
        exit 1
    fi
    sed -n 's/.*msg="loading plugin" id=\([^ ]*\) type=.*/\1/p' "$run_dir/log" \
        | LC_ALL=C sort -u >"$scratch/actual-$name"
    if [[ "$name" == policy ]] && grep -Eq 'level=(error|fatal)|failed to load plugin|skip loading plugin' "$run_dir/log"; then
        cat "$run_dir/log" >&2
        echo "enabled containerd plugin failed to load" >&2
        exit 1
    fi
    kill "$active_pid"
    wait "$active_pid"
    active_pid=""
}

run_inventory full "$scratch/baseline.toml"
run_inventory policy "$config"

if ! cmp -s "$scratch/expected-full" "$scratch/actual-full"; then
    diff -u "$scratch/expected-full" "$scratch/actual-full" >&2 || true
    echo "pinned containerd plugin inventory changed" >&2
    exit 1
fi
if ! cmp -s "$scratch/expected-policy" "$scratch/actual-policy"; then
    diff -u "$scratch/expected-policy" "$scratch/actual-policy" >&2 || true
    echo "containerd policy plugin inventory mismatch" >&2
    exit 1
fi

echo "containerd plugin policy passed"

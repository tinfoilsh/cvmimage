#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-nvidia-producer-test.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

source "$repo_dir/kernel/build-nvidia-open-local.sh"

release=7.0.0-28-generic
source_dir="$scratch/kernel"
module_dir="$scratch/modules"
mkdir -p "$source_dir" "$module_dir"

cat > "$source_dir/vmlinux.symvers" <<'EOF'
0x00000001 pci_iounmap
0x00000002 iterate_fd
0x00000003 init_pid_ns
0x00000004 pci_restore_state
EOF
for module in "${required_modules[@]}"; do
    printf module > "$module_dir/$module"
done

module_vermagic() {
    printf '%s SMP preempt mod_unload modversions\n' "$release"
}

module_versions() {
    cat <<'EOF'
0x00000001 pci_iounmap
0x00000002 iterate_fd
0x00000003 init_pid_ns
0x00000004 pci_restore_state
EOF
}

expect_failure() {
    local label=$1
    shift
    if ("$@") > "$scratch/failure.log" 2>&1; then
        echo "accepted $label" >&2
        exit 1
    fi
}

validate_nvidia_modules "$source_dir" "$module_dir" "$release"

for module in "${required_modules[@]}"; do
    mv "$module_dir/$module" "$module_dir/$module.missing"
    expect_failure "missing $module" validate_nvidia_modules "$source_dir" "$module_dir" "$release"
    mv "$module_dir/$module.missing" "$module_dir/$module"
done

(
    module_vermagic() { printf '%s\n' 'wrong-release SMP'; }
    expect_failure "wrong vermagic" validate_nvidia_modules "$source_dir" "$module_dir" "$release"
)

(
    module_versions() {
        cat <<'EOF'
0x00000001 pci_iounmap
0x00000002 iterate_fd
0x00000003 init_pid_ns
0x00000005 pci_restore_state
EOF
    }
    expect_failure "wrong symbol CRC" validate_nvidia_modules "$source_dir" "$module_dir" "$release"
)

echo "NVIDIA named module producer tests passed"

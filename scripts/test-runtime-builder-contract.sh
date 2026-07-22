#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-runtime-builder-test.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

base_image="$(<"$repo_dir/scripts/runtime-builder-base-image.txt")"
snapshot="$(<"$repo_dir/scripts/runtime-builder-snapshot.txt")"
builder_tag="${snapshot%%T*}"
recipe_sha256="$(
    cd "$repo_dir"
    sha256sum \
        builder/Dockerfile \
        builder/build-initrd.sh \
        scripts/runtime-builder-base-image.txt \
        scripts/runtime-builder-snapshot.txt | sha256sum | awk '{print $1}'
)"
log="$scratch/docker.log"
mkdir -p "$scratch/bin"

cat > "$scratch/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

printf '%q ' "$@" >> "$FAKE_DOCKER_LOG"
printf '\n' >> "$FAKE_DOCKER_LOG"

if [ "${1-}" = image ] && [ "${2-}" = inspect ]; then
    case "${4-}" in
        *runtime-builder.base*) printf '%s\n' "$EXPECTED_BASE" ;;
        *runtime-builder.snapshot*) printf '%s\n' "$EXPECTED_SNAPSHOT" ;;
        *runtime-builder.recipe*) printf '%s\n' "$EXPECTED_RECIPE" ;;
        *runtime\ builder*) printf '%s\n' 'runtime builder: sha256:test' ;;
    esac
fi
EOF
chmod 0755 "$scratch/bin/docker"

export EXPECTED_BASE="$base_image"
export EXPECTED_SNAPSHOT="$snapshot"
export EXPECTED_RECIPE="$recipe_sha256"
export FAKE_DOCKER_LOG="$log"
export PATH="$scratch/bin:$PATH"

"$repo_dir/scripts/build-runtime-builder.sh" >/dev/null
grep -Fq "APT_SNAPSHOT_DATE=$snapshot" "$log"
grep -Fq "cvmimage-runtime-builder:$builder_tag" "$log"

run_nvidia() {
    local requested=$1
    local expected=$requested
    local -a environment=(env)

    : > "$log"
    if [ "$requested" = unset ]; then
        environment+=(-u TINFOIL_OFFLINE)
        expected=0
    else
        environment+=("TINFOIL_OFFLINE=$requested")
    fi
    environment+=(
        "TINFOIL_KERNEL_BUILD_ROOT=$scratch/kernel-build"
        "TINFOIL_KERNEL_OUT_DIR=$scratch/kernel-output"
        "TINFOIL_NVIDIA_OUTPUT_DIR=$scratch/nvidia-output"
        "TINFOIL_NVIDIA_PACKAGE_CACHE=$scratch/nvidia-cache"
        "TINFOIL_RUNTIME_BUILDER_CACHE=$scratch/cache"
        "$repo_dir/scripts/run-runtime-builder.sh"
        nvidia
    )
    "${environment[@]}"
    grep -Fq "TINFOIL_OFFLINE=$expected" "$log"
}

run_nvidia unset
run_nvidia 1

if grep -Fq "$snapshot" \
    "$repo_dir/scripts/build-runtime-builder.sh" \
    "$repo_dir/scripts/run-runtime-builder.sh"; then
    echo 'runtime builder scripts duplicate the shared snapshot value' >&2
    exit 1
fi
grep -Fq 'apt-get clean' "$repo_dir/builder/Dockerfile"

echo 'runtime builder contract tests passed'

#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cvmimage-runtime-lock-test.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

fixture="$scratch/fixture"
fake_bin="$scratch/bin"
mkdir -p "$fixture/scripts" "$fixture/image" "$fake_bin"
cp -- "$repo_dir/scripts/update-runtime-locks.sh" "$fixture/scripts/"
printf '%s\n' 'packages:' > "$fixture/image/runtime-packages.yaml"

cat > "$fake_bin/bazel" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${1:-}" = "--version" ]; then
    printf '%s\n' 'bazel 8.7.0'
    exit 0
fi

output_base=
for argument in "$@"; do
    case "$argument" in
        --output_base=*) output_base=${argument#*=} ;;
    esac
done

case " $* " in
    *" build "*)
        execution_root="$output_base/execroot/cvmimage_lock_update"
        mkdir -p "$execution_root/bazel-out/fake"
        printf '%s\n' 'generated lock' > "$execution_root/bazel-out/fake/runtime-packages.lock.json"
        ;;
    *" cquery "*)
        printf '%s\n' 'bazel-out/fake/runtime-packages.lock.json'
        ;;
    *" info "*" execution_root "*)
        printf '%s\n' "$output_base/execroot/cvmimage_lock_update"
        printf '%s\n' info >> "$FAKE_BAZEL_LOG"
        ;;
    *" mod deps "*)
        printf '%s\n' mod-deps >> "$FAKE_BAZEL_LOG"
        if [ "${FAKE_MOD_DEPS_FAIL:-0}" -eq 1 ]; then
            exit 23
        fi
        ;;
    *)
        printf 'unexpected fake bazel invocation: %q ' "$@" >&2
        printf '\n' >&2
        exit 2
        ;;
esac
EOF
chmod +x "$fake_bin/bazel"

cat > "$fake_bin/mv" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

source_path=${3:?}
destination_path=${4:?}
if [ "$(dirname -- "$source_path")" != "$(dirname -- "$destination_path")" ]; then
    echo "replacement rename crossed directories" >&2
    exit 1
fi
printf '%s\n' same-directory >> "$FAKE_MV_LOG"
exec /usr/bin/mv "$@"
EOF
chmod +x "$fake_bin/mv"

export PATH="$fake_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export BAZEL="$fake_bin/bazel"
export TMPDIR="$scratch/tmp"
export FAKE_BAZEL_LOG="$scratch/bazel.log"
export FAKE_MV_LOG="$scratch/mv.log"
mkdir -p "$TMPDIR"

printf '%s\n' 'generated lock' > "$fixture/image/runtime-packages.lock.json"
"$fixture/scripts/update-runtime-locks.sh" --check
test "$(grep -c '^info$' "$FAKE_BAZEL_LOG")" -eq 2
printf '%s\n' 'OK: cquery outputs resolve through bazel info execution_root'

printf '%s\n' 'checked-in lock' > "$fixture/image/runtime-packages.lock.json"
if "$fixture/scripts/update-runtime-locks.sh" --check; then
    echo 'check unexpectedly accepted a stale runtime package lock' >&2
    exit 1
fi
grep -qx 'checked-in lock' "$fixture/image/runtime-packages.lock.json"
printf '%s\n' 'OK: check rejects a stale runtime package lock'

if FAKE_MOD_DEPS_FAIL=1 "$fixture/scripts/update-runtime-locks.sh"; then
    echo 'update unexpectedly succeeded after module validation failure' >&2
    exit 1
fi
grep -qx 'checked-in lock' "$fixture/image/runtime-packages.lock.json"
printf '%s\n' 'OK: module validation failure preserves the checked-in lock'

"$fixture/scripts/update-runtime-locks.sh"
grep -qx 'generated lock' "$fixture/image/runtime-packages.lock.json"
grep -qx 'same-directory' "$FAKE_MV_LOG"
test "$(stat -c '%a' "$fixture/image/runtime-packages.lock.json")" = 644
printf '%s\n' 'OK: updates use an atomic same-directory replacement'

#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

source_root="$scratch/source"
output_root="$scratch/output"
fake_go="$scratch/go"
test_builder="$scratch/build-go-commands.sh"
log="$scratch/go.log"

mkdir -p "$source_root/tinfoil"
printf 'module tinfoil\n' > "$source_root/tinfoil/go.mod"

cat > "$fake_go" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${1-}" = version ]; then
    echo 'go version go1.25.7 linux/amd64'
    exit 0
fi

test "${CGO_ENABLED-}" = 0
test "${GOTOOLCHAIN-}" = local
test "${SOURCE_DATE_EPOCH-}" = 0
test "$1" = build
test "$2" = -trimpath
test "$3" = -buildvcs=false
test "$4" = -mod=readonly
test "$5" = '-ldflags=-s -w -buildid='
test "$6" = -o
test "$#" -eq 8

output=$7
package=$8
printf '%s\t%s\n' "$(basename "$output")" "$package" >> "$FAKE_GO_LOG"
printf 'fixed output\n' > "$output"
EOF
chmod 0755 "$fake_go"

grep -Fqx 'go_bin=/usr/lib/go-1.25/bin/go' "$repo_dir/builder/build-initrd.sh"
sed "s#^go_bin=.*#go_bin=$fake_go#" \
    "$repo_dir/builder/build-initrd.sh" > "$test_builder"
chmod 0755 "$test_builder"

FAKE_GO_LOG="$log" "$test_builder" "$source_root" "$output_root"

cat > "$scratch/expected" <<'EOF'
tinfoil-boot	./cmd/boot
tinfoil-container-status	./cmd/container-status
tinfoil-egress	./cmd/egress
tinfoil-init	./cmd/init
tinfoil-initrd	./cmd/initrd
tinfoil-shim	./cmd/shim
EOF

cmp "$scratch/expected" "$log"

while IFS=$'\t' read -r name _; do
    binary="$output_root/artifacts/$name"
    test -x "$binary"
    test "$(stat -c %Y "$binary")" -eq 0
done < "$scratch/expected"

test "$(find "$output_root/artifacts" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 6

make -n --no-print-directory -C "$repo_dir" go-binaries > "$scratch/make-plan"
if grep -Fq 'go build' "$scratch/make-plan"; then
    echo 'go-binaries must not use the host Go toolchain' >&2
    exit 1
fi
for name in tinfoil-boot tinfoil-container-status tinfoil-egress tinfoil-init tinfoil-shim; do
    grep -Fq \
        "build/builder-work/output/artifacts/$name mkosi.extra/usr/bin/$name" \
        "$scratch/make-plan"
done

echo 'go producer contract tests: ok'

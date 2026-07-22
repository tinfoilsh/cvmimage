#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

for tool in cc file readelf; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "required tool is unavailable: $tool" >&2
        exit 1
    }
done

source_root="$scratch/source"
output_root="$scratch/output"
fake_go="$scratch/go"
test_builder="$scratch/build-go-commands.sh"
log="$scratch/go.log"
mkdir -p "$scratch/bin" "$source_root/tinfoil"
printf 'module tinfoil\n' > "$source_root/tinfoil/go.mod"

cat > "$scratch/bin/dpkg-query" <<'EOF_DPKG'
#!/usr/bin/env bash
set -Eeuo pipefail

case "${@: -1}" in
    gcc) printf '%s' '4:15.2.0-5ubuntu1' ;;
    binutils) printf '%s' '2.46-3ubuntu2' ;;
    *) exit 1 ;;
esac
EOF_DPKG
chmod 0755 "$scratch/bin/dpkg-query"

cat > "$fake_go" <<'EOF_GO'
#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${1-}" = version ]; then
    echo 'go version go1.25.7 linux/amd64'
    exit 0
fi

test "${GOTOOLCHAIN-}" = local
test "${SOURCE_DATE_EPOCH-}" = 0
test "$1" = build
test "$2" = -trimpath
test "$3" = -buildvcs=false
test "$4" = -mod=readonly
test "$6" = -o
test "$#" -eq 8

ldflags=$5
output=$7
package=$8
name="$(basename "$output")"
source_file="$output.c"
cat > "$source_file" <<'EOF_SOURCE'
int main(void) { return 0; }
EOF_SOURCE

if [ "$name" = tinfoil-initrd ]; then
    test "${CGO_ENABLED-}" = 0
    test "$ldflags" = '-ldflags=-s -w -buildid='
    "$FAKE_CC" -static -s -Wl,--build-id=none -o "$output" "$source_file"
else
    test "${CGO_ENABLED-}" = 1
    test "${CC-}" = /usr/bin/gcc
    test "$ldflags" = '-ldflags=-s -w -buildid= -linkmode=external -extld=/usr/bin/gcc -extldflags=-Wl,--build-id=none'
    "$FAKE_CC" -s -Wl,--build-id=none -o "$output" "$source_file"
fi
rm -f "$source_file"
printf '%s\t%s\t%s\n' "$name" "$package" "$CGO_ENABLED" >> "$FAKE_GO_LOG"
EOF_GO
chmod 0755 "$fake_go"

grep -Fqx 'go_bin=/usr/lib/go-1.25/bin/go' "$repo_dir/builder/build-initrd.sh"
sed "s#^go_bin=.*#go_bin=$fake_go#" \
    "$repo_dir/builder/build-initrd.sh" > "$test_builder"
chmod 0755 "$test_builder"

FAKE_CC="$(command -v cc)" FAKE_GO_LOG="$log" PATH="$scratch/bin:$PATH" \
    "$test_builder" "$source_root" "$output_root"

cat > "$scratch/expected" <<'EOF_EXPECTED'
tinfoil-boot	./cmd/boot	1
tinfoil-container-status	./cmd/container-status	1
tinfoil-egress	./cmd/egress	1
tinfoil-init	./cmd/init	1
tinfoil-initrd	./cmd/initrd	0
tinfoil-shim	./cmd/shim	1
EOF_EXPECTED

cmp "$scratch/expected" "$log"

while IFS=$'\t' read -r name _ cgo_enabled; do
    binary="$output_root/artifacts/$name"
    test -x "$binary"
    test "$(stat -c %Y "$binary")" -eq 0
    if readelf -nW "$binary" | grep -Fq 'Build ID'; then
        echo "$name contains an ELF build ID" >&2
        exit 1
    fi
    if [ "$cgo_enabled" = 0 ]; then
        file "$binary" | grep -Fq 'statically linked'
        if readelf -lW "$binary" | grep -Fq 'INTERP'; then
            echo "$name unexpectedly contains an ELF interpreter" >&2
            exit 1
        fi
    else
        file "$binary" | grep -Fq 'dynamically linked'
        readelf -lW "$binary" | grep -Fq 'INTERP'
        readelf -dW "$binary" | grep -Fq 'Shared library: [libc.so.6]'
    fi
done < "$scratch/expected"

test "$(find "$output_root/artifacts" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 6

echo 'go producer contract tests: ok'

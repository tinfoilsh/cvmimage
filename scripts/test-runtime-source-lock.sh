#!/usr/bin/env bash
set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C

repo_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
lock="$repo_dir/image/runtime-sources.lock.json"
tool="$repo_dir/scripts/runtime_source_lock.py"
scratch=$(mktemp -d /tmp/cvmimage-runtime-source-test.XXXXXX)
hostile_link=
hostile_directory=
cleanup() {
    [ -z "$hostile_link" ] || rm -f -- "$hostile_link"
    if [ -n "$hostile_directory" ]; then
        rm -f -- "$hostile_directory/.cvmimage-runtime-lock-owner"
        rmdir -- "$hostile_directory" 2>/dev/null || true
    fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT

source "$repo_dir/scripts/update-runtime-locks.sh"

python3 "$tool" validate "$lock"
python3 "$tool" validate-dependencies "$lock" "$repo_dir/image/runtime-packages.lock.json"

python3 - "$lock" "$scratch" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
data = json.loads(source.read_text())

mutations = {}
bad = json.loads(source.read_text())
bad["sources"][0]["members"].append("docker/docker-init")
bad["sources"][0]["members"].sort()
mutations["docker-extra.json"] = bad

bad = json.loads(source.read_text())
bad["sources"][1]["sha256"] = "0" * 63
mutations["bad-digest.json"] = bad

bad = json.loads(source.read_text())
bad["sources"][1]["files"][0]["sha256"] = "z" * 64
mutations["bad-file-digest.json"] = bad

bad = json.loads(source.read_text())
bad["sources"][1]["files"][0]["size"] = "1"
mutations["bad-file-size.json"] = bad

bad = json.loads(source.read_text())
bad["sources"][1]["files"][0]["path"] = "usr/lib/x86_64-linux-gnu/unselected.so"
mutations["unselected-generated-file.json"] = bad

bad = json.loads(source.read_text())
bad["sources"][0]["files"].pop()
mutations["missing-generated-member.json"] = bad

bad = json.loads(source.read_text())
fabric = next(item for item in bad["sources"] if item["id"] == "nvidia-fabricmanager")
fabric["complete_directories"] = []
mutations["missing-topology-policy.json"] = bad

bad = json.loads(source.read_text())
persistenced = next(item for item in bad["sources"] if item["id"] == "nvidia-persistenced")
persistenced["control_dependency_exceptions"] = {}
mutations["missing-control-exception.json"] = bad

bad = json.loads(source.read_text())
compute = next(item for item in bad["sources"] if item["id"] == "libnvidia-compute")
compute["paths"].append("usr/bin/nvidia-smi")
compute["paths"].sort()
mutations["forbidden-payload.json"] = bad

for fragment in ("libcudadebugger", "libnvidia-opticalflow"):
    bad = json.loads(source.read_text())
    compute = next(item for item in bad["sources"] if item["id"] == "libnvidia-compute")
    compute["paths"].append(f"usr/lib/x86_64-linux-gnu/{fragment}.so.1")
    compute["paths"].sort()
    mutations[f"forbidden-{fragment}.json"] = bad

for name, value in mutations.items():
    (root / name).write_text(json.dumps(value))
PY

for mutation in "$scratch"/*.json; do
    if python3 "$tool" validate "$mutation" >/dev/null 2>&1; then
        echo "mutation unexpectedly validated: $mutation" >&2
        exit 1
    fi
done

python3 - "$lock" "$scratch/alternative-source-lock.json" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
data = json.loads(source.read_text())
fabric = next(item for item in data["sources"] if item["id"] == "nvidia-fabricmanager")
fabric["control"]["depends"] = "missing-package (= 1) | libc6 (>= 2.34)"
destination.write_text(json.dumps(data))
PY
python3 "$tool" validate-dependencies \
    "$scratch/alternative-source-lock.json" "$repo_dir/image/runtime-packages.lock.json"

python3 - "$repo_dir/image/runtime-packages.lock.json" "$scratch/bad-package-lock.json" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
data = json.loads(source.read_text())
libc = next(package for package in data["packages"] if package["name"] == "libc6")
libc["version"] = "1.0"
destination.write_text(json.dumps(data))
PY
if python3 "$tool" validate-dependencies "$lock" "$scratch/bad-package-lock.json" >/dev/null 2>&1; then
    echo "incompatible locked dependency unexpectedly validated" >&2
    exit 1
fi

printf 'old\n' > "$scratch/destination"
printf 'new\n' > "$scratch/source"
python3 "$tool" atomic-replace "$scratch/source" "$scratch/destination"
cmp "$scratch/source" "$scratch/destination"
if find "$scratch" -maxdepth 1 -name '.destination.new-*' | grep -q .; then
    echo "atomic replacement left a temporary file" >&2
    exit 1
fi

grep -Fq 'mktemp -d /tmp/cvmimage-runtime-lock.XXXXXXXX' "$repo_dir/scripts/update-runtime-locks.sh"
grep -Fq 'tree_a=$scratch/a' "$repo_dir/scripts/update-runtime-locks.sh"
grep -Fq 'tree_b=$scratch/b' "$repo_dir/scripts/update-runtime-locks.sh"
grep -Fq "trap 'exit 130' INT" "$repo_dir/scripts/update-runtime-locks.sh"
grep -Fq "trap 'exit 143' TERM" "$repo_dir/scripts/update-runtime-locks.sh"
grep -Fq 'cmp -- "$tree_a/generated/runtime-packages.lock.json" "$tree_b/generated/runtime-packages.lock.json"' "$repo_dir/scripts/update-runtime-locks.sh"
grep -Fq 'cmp -- "$tree_a/generated/runtime-sources.lock.json" "$repo_dir/image/runtime-sources.lock.json"' "$repo_dir/scripts/update-runtime-locks.sh"
if grep -Eq 'tail[[:space:]]+-n[[:space:]]+1|--network[=[:space:]]+host|CVMIMAGE.*ROOT|rm -rf -- /tmp/' "$repo_dir/scripts/update-runtime-locks.sh"; then
    echo "unsafe updater mechanism found" >&2
    exit 1
fi

outside="$scratch/outside"
mkdir "$outside"
printf 'keep\n' > "$outside/sentinel"
hostile_link=$(mktemp -d /tmp/cvmimage-runtime-lock.XXXXXXXX)
rmdir -- "$hostile_link"
ln -s "$outside" "$hostile_link"
if cleanup_runtime_lock_tree "$hostile_link" test-token 2>/dev/null; then
    echo "cleanup accepted a symlink root" >&2
    exit 1
fi
test -f "$outside/sentinel"

hostile_directory=$(mktemp -d /tmp/cvmimage-runtime-lock.XXXXXXXX)
printf 'wrong-token\n' > "$hostile_directory/.cvmimage-runtime-lock-owner"
if cleanup_runtime_lock_tree "$hostile_directory" test-token 2>/dev/null; then
    echo "cleanup accepted an unowned preexisting directory" >&2
    exit 1
fi
test -d "$hostile_directory"

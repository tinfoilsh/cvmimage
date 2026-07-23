#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
base_image="$(<"$repo_dir/scripts/runtime-builder-base-image.txt")"
snapshot="$(<"$repo_dir/scripts/runtime-builder-snapshot.txt")"
builder_image="cvmimage-runtime-builder:${snapshot%%T*}"
recipe_sha256="$(
    cd "$repo_dir"
    sha256sum \
        builder/Dockerfile \
        builder/build-initrd.sh \
        scripts/runtime-builder-base-image.txt \
        scripts/runtime-builder-snapshot.txt | sha256sum | awk '{print $1}'
)"

if [[ ! "$base_image" =~ ^ubuntu@sha256:[0-9a-f]{64}$ ]]; then
    echo "invalid runtime builder base image: $base_image" >&2
    exit 1
fi
if [[ ! "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
    echo "invalid runtime builder snapshot: $snapshot" >&2
    exit 1
fi

docker build \
    --pull \
    --build-arg "RUNTIME_BUILDER_BASE_IMAGE=$base_image" \
    --build-arg "APT_SNAPSHOT_DATE=$snapshot" \
    --build-arg "RUNTIME_BUILDER_RECIPE_SHA256=$recipe_sha256" \
    --file "$repo_dir/builder/Dockerfile" \
    --tag "$builder_image" \
    "$repo_dir/builder"

actual_base="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.base" }}' "$builder_image")"
actual_snapshot="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.snapshot" }}' "$builder_image")"
actual_recipe="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.recipe" }}' "$builder_image")"
if [ "$actual_base" != "$base_image" ] ||
    [ "$actual_snapshot" != "$snapshot" ] ||
    [ "$actual_recipe" != "$recipe_sha256" ]; then
    echo "runtime builder label mismatch" >&2
    exit 1
fi

docker image inspect --format 'runtime builder: {{.Id}}' "$builder_image"

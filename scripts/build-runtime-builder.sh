#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
base_image="$(<"$repo_dir/scripts/runtime-builder-base-image.txt")"
builder_image=cvmimage-runtime-builder:20260721
recipe_sha256="$(
    cd "$repo_dir"
    sha256sum \
        builder/Dockerfile \
        builder/build-initrd.sh \
        scripts/runtime-builder-base-image.txt | sha256sum | awk '{print $1}'
)"

if [[ ! "$base_image" =~ ^ubuntu@sha256:[0-9a-f]{64}$ ]]; then
    echo "invalid runtime builder base image: $base_image" >&2
    exit 1
fi

docker build \
    --pull \
    --build-arg "RUNTIME_BUILDER_BASE_IMAGE=$base_image" \
    --build-arg APT_SNAPSHOT_DATE=20260721T000000Z \
    --build-arg "RUNTIME_BUILDER_RECIPE_SHA256=$recipe_sha256" \
    --file "$repo_dir/builder/Dockerfile" \
    --tag "$builder_image" \
    "$repo_dir"

actual_base="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.base" }}' "$builder_image")"
actual_snapshot="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.snapshot" }}' "$builder_image")"
actual_recipe="$(docker image inspect --format '{{ index .Config.Labels "org.tinfoil.runtime-builder.recipe" }}' "$builder_image")"
if [ "$actual_base" != "$base_image" ] ||
    [ "$actual_snapshot" != 20260721T000000Z ] ||
    [ "$actual_recipe" != "$recipe_sha256" ]; then
    echo "runtime builder label mismatch" >&2
    exit 1
fi

docker image inspect --format 'runtime builder: {{.Id}}' "$builder_image"

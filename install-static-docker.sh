#!/usr/bin/env bash
set -Eeuo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

docker_static_version="29.5.3"
docker_static_sha256="34eea64e9c3435f5af1b760827a56a561cd67fc2d6e9cd1813b8bb1e3ff7930b"
docker_static_url="https://download.docker.com/linux/static/stable/x86_64/docker-${docker_static_version}.tgz"

cache_dir="mkosi.cache/docker-static"
tarball="${cache_dir}/docker-${docker_static_version}.tgz"
extract_dir="${cache_dir}/docker-${docker_static_version}"
dest_dir="mkosi.extra/usr/bin"

mkdir -p "$cache_dir" "$dest_dir"

if [ ! -f "$tarball" ] || ! printf '%s  %s\n' "$docker_static_sha256" "$tarball" | sha256sum -c --status; then
    tmp="${tarball}.tmp"
    curl -fsSL "$docker_static_url" -o "$tmp"
    printf '%s  %s\n' "$docker_static_sha256" "$tmp" | sha256sum -c --status
    mv "$tmp" "$tarball"
fi

rm -rf "$extract_dir"
mkdir -p "$extract_dir"
tar -C "$extract_dir" --strip-components=1 -xzf "$tarball"

for bin in \
    containerd \
    containerd-shim-runc-v2 \
    ctr \
    docker \
    docker-init \
    docker-proxy \
    dockerd \
    runc; do
    install -m0755 "$extract_dir/$bin" "$dest_dir/$bin"
done

for bin in containerd containerd-shim-runc-v2 ctr docker docker-init docker-proxy dockerd runc; do
    # A binary we cannot inspect must fail the build; a silently-skipped
    # check would let an unvetted binary into the image.
    if ! deps="$(readelf -d "$dest_dir/$bin" 2>&1)"; then
        echo "ERROR: cannot inspect staged Docker binary $bin" >&2
        printf '%s\n' "$deps" >&2
        exit 1
    fi
    if grep -Eq 'lib(systemd|udev)\.so' <<<"$deps"; then
        echo "ERROR: static Docker binary $bin links systemd/udev" >&2
        printf '%s\n' "$deps" >&2
        exit 1
    fi
done

echo "installed static Docker ${docker_static_version}"

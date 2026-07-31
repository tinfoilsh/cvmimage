#!/usr/bin/env bash
# Install the pinned official Nix release with the exact configuration the
# image build requires. CI, release builders, operators, and auditors all
# install through this one script, so the toolchain cannot drift between them.
set -Eeuo pipefail

pin_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="$(< "$pin_dir/nix-version")"
sha256="$(< "$pin_dir/nix-x86_64-linux.sha256")"
store_path="$(< "$pin_dir/nix-x86_64-linux-store-path")"
release="nix-$version-x86_64-linux"
profile=/nix/var/nix/profiles/default

expect() { # expect <name> <actual> <wanted>
  [[ "$2" == "$3" ]] ||
    { echo "unexpected $1: '$2' (wanted '$3')" >&2; exit 1; }
}

# A machine with any pre-existing Nix is not a supported builder.
if command -v nix > /dev/null || [[ -e /nix ]]; then
  echo 'refusing an unverified preinstalled Nix' >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fetch the official release and verify it against the committed checksum.
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$tmp/$release.tar.xz" \
  "https://releases.nixos.org/nix/nix-$version/$release.tar.xz"
echo "$sha256  $tmp/$release.tar.xz" | sha256sum --check --strict
tar --extract --xz --file "$tmp/$release.tar.xz" --directory "$tmp"

# Install with the exact settings the build requires; a sandbox setup failure
# must stop the build rather than weaken its isolation.
cat > "$tmp/nix.conf" << 'EOF'
sandbox = true
sandbox-fallback = false
restrict-eval = true
allowed-uris = https://github.com/NixOS/nixpkgs/archive/
EOF
"$tmp/$release/install" \
  --daemon --yes --no-channel-add --no-modify-profile \
  --nix-extra-conf-file "$tmp/nix.conf"

# Assert the installed store path, version, and settings. Every tool in the
# release, nix-daemon included, is a symlink to the multi-call nix binary, so
# full resolution lands on bin/nix.
nix="$profile/bin/nix"
expect nix-store-path "$(readlink -f "$nix")" "$store_path/bin/nix"
expect daemon-store-path \
  "$(readlink -f "$profile/bin/nix-daemon")" "$store_path/bin/nix"
expect version "$("$nix" --version)" "nix (Nix) $version"

# config show is behind the nix-command feature gate; enable it for these
# read-only assertions only, never in the installed configuration.
show() { "$nix" --extra-experimental-features nix-command config show "$1"; }
expect sandbox "$(show sandbox)" true
expect sandbox-fallback "$(show sandbox-fallback)" false
expect restrict-eval "$(show restrict-eval)" true
expect allowed-uris \
  "$(show allowed-uris)" 'https://github.com/NixOS/nixpkgs/archive/'

echo "installed pinned Nix $version with sandboxed, restricted evaluation"

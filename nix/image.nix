{
  pkgs,
  rootfs,
  debugLayer ? null,
  kernel,
  initrd,
  repartDefinitions,
  repartSeed,
  basename,
}:

pkgs.runCommand "${basename}-image"
  {
    allowedReferences = [ ];
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.e2fsprogs
      pkgs.fakeroot
      pkgs.gnutar
      pkgs.jq
      pkgs.systemd
    ];
  }
  ''
    set -euo pipefail
    root="$TMPDIR/root"
    mkdir -p "$root" "$out"

    fakeroot -- ${pkgs.bash}/bin/bash -euo pipefail -c '
      rootfs="$1"
      debug_layer="$2"
      root="$3"
      output="$4"
      definitions="$5"
      seed="$6"

      tar --extract --file="$rootfs" --directory="$root" \
        --numeric-owner --same-owner --same-permissions
      if test -n "$debug_layer"; then
        tar --extract --file="$debug_layer" --directory="$root" \
          --numeric-owner --same-owner --same-permissions
      fi

      export SOURCE_DATE_EPOCH=0
      systemd-repart \
        --empty=create \
        --size=auto \
        --dry-run=no \
        --offline=yes \
        --discard=no \
        --seed="$seed" \
        --definitions="$definitions" \
        --copy-source="$root" \
        --json=short \
        --pretty=no \
        --no-pager \
        "$output" > "$TMPDIR/partitions.json"
    ' bash \
      ${rootfs} \
      ${if debugLayer == null then ''""'' else toString debugLayer} \
      "$root" \
      "$out/${basename}.raw" \
      ${repartDefinitions} \
      ${repartSeed}

    jq --exit-status --join-output --raw-output '
      [.[] | select(.type == "root-x86-64-verity") | .roothash]
      | if length == 1 and (.[0] | test("^[0-9a-f]{64}$"))
        then .[0]
        else error("missing, duplicate, or malformed root hash")
        end
    ' "$TMPDIR/partitions.json" > "$out/${basename}.roothash"

    install -m 0644 ${kernel} "$out/${basename}.vmlinuz"
    install -m 0644 ${initrd} "$out/${basename}.initrd"

    test -s "$out/${basename}.raw"
    test -s "$out/${basename}.vmlinuz"
    test -s "$out/${basename}.initrd"
    test "$(wc -c < "$out/${basename}.roothash")" -eq 64
  ''

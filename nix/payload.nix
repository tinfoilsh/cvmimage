{ pkgs }:
let
  inherit (pkgs) lib;
in
rec {
  fetchDeb =
    package:
    pkgs.fetchurl {
      name = "${package.name}.deb";
      urls = package.urls or [ package.url ];
      sha256 = package.sha256;
    };
  # Capture guest modes before Nix normalizes the store directory permissions.
  # The directory output is only for build-time tools such as CA generation.
  debTree =
    name: debs:
    pkgs.runCommand name
      {
        outputs = [
          "out"
          "archive"
        ];
      }
      ''
        set -euo pipefail
        mkdir -p "$out"
        ${lib.concatMapStringsSep "\n" (deb: ''
          ${pkgs.dpkg}/bin/dpkg-deb --fsys-tarfile ${deb} |
            ${pkgs.gnutar}/bin/tar --extract --file=- --directory "$out" \
              --no-same-owner --keep-old-files
        '') debs}
        ${pkgs.gnutar}/bin/tar --create --file "$archive" --directory "$out" \
          --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu .
      '';
  archiveTree =
    {
      name,
      archive,
      stripComponents ? 0,
    }:
    pkgs.runCommand name { } ''
      mkdir -p "$out"
      ${pkgs.gnutar}/bin/tar --extract --file ${archive} --directory "$out" \
        --strip-components=${toString stripComponents} --no-same-owner --keep-old-files
    '';
  caBundle =
    ubuntu:
    pkgs.runCommand "ca-certificates.crt"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnused
          pkgs.openssl
        ];
      }
      ''
        mkdir "$TMPDIR/certs"
        touch "$TMPDIR/ca-certificates.conf"
        ${pkgs.dash}/bin/dash -e ${ubuntu}/usr/sbin/update-ca-certificates \
          --default --certsconf "$TMPDIR/ca-certificates.conf" \
          --certsdir ${ubuntu}/usr/share/ca-certificates \
          --localcertsdir "$TMPDIR/no-local-certificates" \
          --etccertsdir "$TMPDIR/certs" --hooksdir "$TMPDIR/no-ca-hooks"
        cp "$TMPDIR/certs/ca-certificates.crt" "$out"
      '';
  accounts =
    directory:
    map
      (entry: {
        source = directory + "/${entry.name}";
        target = "etc/${entry.name}";
        inherit (entry) mode;
      })
      [
        {
          name = "group";
          mode = "0644";
        }
        {
          name = "gshadow";
          mode = "0640";
        }
        {
          name = "passwd";
          mode = "0644";
        }
        {
          name = "shadow";
          mode = "0640";
        }
      ];
  binaries =
    runtime: commands:
    map (command: {
      source = "${runtime}/bin/tinfoil-${command}";
      target = "usr/bin/tinfoil-${command}";
      mode = "0755";
    }) commands;
  merge =
    manifests:
    lib.genAttrs [ "payloads" "files" "replacements" "directories" "symlinks" ] (
      field: lib.concatMap (manifest: manifest.${field} or [ ]) manifests
    );
}

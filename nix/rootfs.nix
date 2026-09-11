{
  pkgs,
  payloads ? [ ],
  files ? [ ],
  replacements ? [ ],
  directories ? [ ],
  symlinks ? [ ],
}:
let
  inherit (pkgs) lib;
  quote = lib.escapeShellArg;
  installFile = file: ''
    install_new ${quote file.mode} ${quote "${file.source}"} "$root"/${quote file.target}
  '';
in
pkgs.runCommand "cvmimage-rootfs.tar"
  {
    allowedReferences = [ ];
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.gnutar
    ];
  }
  ''
    set -euo pipefail
    umask 0022
    root="$TMPDIR/root"
    mkdir -p "$root"
    install_new() {
      test ! -e "$3"
      test ! -L "$3"
      install -D -m "$1" "$2" "$3"
    }
    ${lib.concatStringsSep "\n" (
      lib.imap0 (index: payload: ''
        source="$TMPDIR/payload-${toString index}"
        mkdir -p "$source"
        tar --extract --file ${quote (toString payload.archive)} --directory "$source" --no-same-owner
        tar --create --file=- --directory "$source" \
          ${lib.escapeShellArgs payload.paths} |
          tar --extract --file=- --directory "$root" --no-same-owner --keep-old-files
      '') payloads
    )}
    ${lib.concatMapStringsSep "\n" installFile files}
    ${lib.concatMapStringsSep "\n" (file: ''
      test -e "$root"/${quote file.target} || test -L "$root"/${quote file.target}
      install -D -m ${quote file.mode} ${quote "${file.source}"} "$root"/${quote file.target}
    '') replacements}
    ${lib.concatMapStringsSep "\n" (directory: ''
      install -d -m ${quote directory.mode} "$root"/${quote directory.path}
    '') directories}
    ${lib.concatMapStringsSep "\n" (link: ''
      test ! -e "$root"/${quote link.target}
      test ! -L "$root"/${quote link.target}
      mkdir -p "$(dirname "$root"/${quote link.target})"
      ln -s ${quote link.source} "$root"/${quote link.target}
    '') symlinks}
    chmod 0755 "$root"
    tar --create --file "$out" --directory "$root" \
      --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --format=gnu .
  ''

{ pkgs }:

let
  tools = pkgs.buildEnv {
    name = "cvmimage-mkosi-tools";
    paths = [ pkgs.systemd pkgs.e2fsprogs pkgs.dosfstools ];
    pathsToLink = [ "/bin" ];
  };
in
pkgs.writeShellScriptBin "mkosi" ''
  exec ${pkgs.mkosi}/bin/mkosi --extra-search-path=${tools}/bin "$@"
''

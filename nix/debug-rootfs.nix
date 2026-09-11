{ pkgs, debugPID1 }:
let
  payload = import ./payload.nix { inherit pkgs; };
  sources = import ./runtime-sources.nix;
in
import ./rootfs.nix {
  inherit pkgs;
  payloads = [
    {
      archive = (payload.debTree "cvmimage-debug-tools" [ (payload.fetchDeb sources.busybox) ]).archive;
      paths = [ "." ];
    }
  ];
  files = payload.binaries debugPID1 [ "pid1" ];
  directories = [
    {
      path = "root";
      mode = "0700";
    }
  ];
}

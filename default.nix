{
  system ? "x86_64-linux",
}:

assert system == "x86_64-linux";

let
  nixpkgsLock = builtins.fromJSON (builtins.readFile ./nixpkgs.lock.json);
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsLock) url sha256;
  };
  pkgs = import nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
  go = import ./nix/go.nix { inherit pkgs; };
  initrd = import ./nix/initrd.nix {
    inherit pkgs;
    inherit (go) upstreamGo;
    tinfoilInitrd = go.packages."tinfoil-initrd";
  };
  kernel = import ./nix/kernel.nix { inherit pkgs; };
  nvidia = import ./nix/nvidia-modules.nix { inherit pkgs kernel; };
  nvattest = import ./nix/nvattest.nix { inherit pkgs; };
in
go.packages
// {
  "fixed-cpio-writer" = initrd.writer;
  initrd = initrd.archive;
  "kernel-artifacts" = kernel.artifacts;
  "nvidia-modules" = nvidia.modules;
  inherit (nvattest) nvattest;
}

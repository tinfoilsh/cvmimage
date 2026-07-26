{
  system ? builtins.currentSystem,
}:

assert system == "x86_64-linux";

let
  nixpkgsLock = builtins.fromJSON (builtins.readFile ./nixpkgs.lock.json);
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsLock) url sha256;
  };
  pkgs = import nixpkgs { inherit system; };
  go = import ./nix/go.nix { inherit pkgs; };
  initrd = import ./nix/initrd.nix {
    inherit pkgs;
    inherit (go) upstreamGo;
    tinfoilInitrd = go.packages."tinfoil-initrd";
  };
  kernel = import ./nix/kernel.nix { inherit pkgs; };
  nvidia = import ./nix/nvidia-modules.nix { inherit pkgs kernel; };
  nvattest = import ./nix/nvattest.nix { inherit pkgs; };
  mkosi = import ./nix/mkosi.nix { inherit pkgs; };
  runtimePackages = import ./nix/runtime-packages.nix { inherit pkgs; };
  rootfs = import ./nix/rootfs.nix {
    inherit pkgs;
    ubuntuDebs = runtimePackages.packages;
    runtimeGo = go.packages."runtime-go";
    debugInit = go.packages."debug-init";
    inherit (nvattest) nvattest;
    nvidiaModules = map (name: "${nvidia.modules}/${name}") [
      "nvidia.ko"
      "nvidia-uvm.ko"
      "nvidia-modeset.ko"
    ];
  };
  imageInputs = pkgs.linkFarm "cvmimage-image-inputs" [
    { name = "rootfs.tar"; path = rootfs.rootfs; }
    { name = "debug-rootfs-layer.tar"; path = rootfs.debugLayer; }
    { name = "initrd.cpio.zst"; path = initrd.archive; }
    { name = "tinfoil-custom.vmlinuz"; path = "${kernel.artifacts}/tinfoil-custom.vmlinuz"; }
  ];
in
go.packages
// {
  "fixed-cpio-writer" = initrd.writer;
  initrd = initrd.archive;
  "kernel-artifacts" = kernel.artifacts;
  "nvidia-modules" = nvidia.modules;
  inherit (nvattest) nvattest;
  "rootfs-archive" = rootfs.rootfs;
  "debug-rootfs-layer" = rootfs.debugLayer;
  "runtime-package-lock" = runtimePackages.lock;
  "image-inputs" = imageInputs;
  inherit mkosi;
}

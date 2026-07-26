{
  system ? builtins.currentSystem,
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
  repartSeedText = builtins.readFile ./repart.d/seed;
  repartSeedMatch = builtins.match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\n" repartSeedText;
  repartSeed = assert repartSeedMatch != null; builtins.head repartSeedMatch;
  image = import ./nix/image.nix;
  shippingImage = image {
    inherit pkgs repartSeed;
    rootfs = rootfs.rootfs;
    kernel = "${kernel.artifacts}/tinfoil-custom.vmlinuz";
    initrd = initrd.archive;
    repartDefinitions = ./repart.d;
    basename = "tinfoilcvm";
  };
  debugImage = image {
    inherit pkgs repartSeed;
    rootfs = rootfs.rootfs;
    debugLayer = rootfs.debugLayer;
    kernel = "${kernel.artifacts}/tinfoil-custom.vmlinuz";
    initrd = initrd.archive;
    repartDefinitions = ./repart.d;
    basename = "tinfoilcvm-debug";
  };
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
  "release-upload-cli" = pkgs.awscli2;
  "shipping-image" = shippingImage;
  "debug-image" = debugImage;
}

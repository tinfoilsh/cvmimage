{ pkgs, gpuSupport }:

let
  go = import ./go.nix { inherit pkgs gpuSupport; };
  initrd = import ./initrd.nix {
    inherit pkgs;
    tinfoilInitrd = go.packages."tinfoil-initrd";
  };
  kernel = import ./kernel.nix { inherit pkgs gpuSupport; };
  debugKernel = import ./kernel.nix {
    inherit pkgs;
    inherit gpuSupport;
    debugConsole = true;
  };
  nvidia = import ./nvidia-modules.nix { inherit pkgs kernel; };
  nvattest = import ./nvattest.nix { inherit pkgs; };
  runtimePackages = import ./runtime-packages.nix { inherit pkgs gpuSupport; };
  rootfs = import ./rootfs.nix {
    inherit pkgs;
    inherit gpuSupport;
    ubuntuDebs = runtimePackages.packages;
    runtimeGo = go.packages."runtime-go";
    debugPID1 = go.packages."debug-pid1";
    nvattest = if gpuSupport then nvattest.nvattest else null;
    nvidiaModules = pkgs.lib.optionals gpuSupport (map (name: "${nvidia.modules}/${name}") nvidia.moduleNames);
  };
  repartSeedText = builtins.readFile ../repart.d/seed;
  repartSeedMatch = builtins.match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\n" repartSeedText;
  repartSeed = assert repartSeedMatch != null; builtins.head repartSeedMatch;
  image = import ./image.nix;
  buildImage = kernelArtifacts: extraArgs: image ({
    inherit pkgs repartSeed;
    rootfs = rootfs.rootfs;
    kernel = "${kernelArtifacts}/tinfoil-custom.vmlinuz";
    inherit initrd;
    repartDefinitions = ../repart.d;
  } // extraArgs);
  shippingImage = buildImage kernel.artifacts {
    basename = "tinfoilcvm";
  };
  debugImage = buildImage debugKernel.artifacts {
    debugLayer = rootfs.debugLayer;
    basename = "tinfoilcvm-debug";
  };
in
go.packages
// {
  inherit (go) checks;
  inherit initrd;
  "kernel-artifacts" = kernel.artifacts;
  "debug-kernel-artifacts" = debugKernel.artifacts;
  "rootfs-archive" = rootfs.rootfs;
  "debug-rootfs-layer" = rootfs.debugLayer;
  "runtime-package-lock" = runtimePackages.lock;
  "shipping-image" = shippingImage;
  "debug-image" = debugImage;
} // pkgs.lib.optionalAttrs gpuSupport {
  "nvidia-modules" = nvidia.modules;
  inherit (nvattest) nvattest;
}

{
  pkgs,
  go,
  platform,
  definition,
}:
let
  payload = import ./payload.nix { inherit pkgs; };
  repartSeedText = builtins.readFile ../repart.d/seed;
  repartSeedMatch = builtins.match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\n" repartSeedText;
  repartSeed =
    assert repartSeedMatch != null;
    builtins.head repartSeedMatch;
  runtime = go.runtime definition.module definition.commands;
  debugPID1 = go.debugPID1 definition.module;
  kernel = import ./kernel.nix {
    inherit pkgs;
    inherit (definition) kernelConfigs;
  };
  debugKernel = import ./kernel.nix {
    inherit pkgs;
    inherit (definition) kernelConfigs;
    debugConsole = true;
  };
  declared = definition.rootfs { inherit kernel; };
  rootfs = import ./rootfs.nix (
    {
      inherit pkgs;
    }
    // payload.merge [
      platform.manifest
      declared.manifest
      { files = payload.binaries runtime definition.commands; }
    ]
  );
  debugLayer = import ./debug-rootfs.nix { inherit pkgs debugPID1; };
  buildImage =
    kernelArtifacts: extra:
    import ./image.nix (
      {
        inherit pkgs repartSeed rootfs;
        inherit (definition) basename;
        inherit (platform) initrd;
        kernel = "${kernelArtifacts}/tinfoil-custom.vmlinuz";
        repartDefinitions = ../repart.d;
      }
      // extra
    );
in
{
  inherit
    runtime
    debugPID1
    kernel
    debugKernel
    rootfs
    debugLayer
    ;
  checks = definition.checks;
  extraOutputs = declared.outputs or { };
  shippingImage = buildImage kernel.artifacts { };
  debugImage = buildImage debugKernel.artifacts {
    inherit debugLayer;
    basename = "${definition.basename}-debug";
  };
}

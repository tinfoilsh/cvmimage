{
  system ? "x86_64-linux",
  schemaSource ? ../tinfoil-config,
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
  go = import ./nix/go.nix { inherit pkgs schemaSource; };
  platform = import ./nix/platform.nix { inherit pkgs go; };
  build =
    definition:
    import ./nix/variant.nix {
      inherit
        pkgs
        go
        platform
        definition
        ;
    };
  inference = build (import ./inference { inherit pkgs go platform; });
  sandbox = build (import ./sandbox { inherit pkgs go platform; });
  producers = prefix: variant: {
    "${prefix}runtime-go" = variant.runtime;
    "${prefix}debug-pid1" = variant.debugPID1;
    "${prefix}kernel-artifacts" = variant.kernel.artifacts;
    "${prefix}debug-kernel-artifacts" = variant.debugKernel.artifacts;
    "${prefix}rootfs-archive" = variant.rootfs;
    "${prefix}debug-rootfs-layer" = variant.debugLayer;
  };
in
producers "" inference
// producers "sandbox-" sandbox
// inference.extraOutputs
// sandbox.extraOutputs
// {
  checks = pkgs.runCommand "cvmimage-checks" {
    checks = [
      platform.checks
      inference.checks
      sandbox.checks
    ];
  } "touch $out";
  "platform-checks" = platform.checks;
  "inference-checks" = inference.checks;
  "sandbox-checks" = sandbox.checks;
  inherit (platform) initrd;
  "tinfoil-initrd" = platform.tinfoilInitrd;
  "release-upload-cli" = pkgs.awscli2;
  "inference-image" = inference.shippingImage;
  "inference-debug-image" = inference.debugImage;
  "sandbox-image" = sandbox.shippingImage;
  "sandbox-debug-image" = sandbox.debugImage;
  "shipping-image" = inference.shippingImage;
  "debug-image" = inference.debugImage;
}

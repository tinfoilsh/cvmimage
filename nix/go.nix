{ pkgs }:

let
  commonEnv.GOTOOLCHAIN = "local";

  nixRuntimePatchSuffixes = [
    "iana-etc-1.25.patch"
    "mailcap-1.17.patch"
    "tzdata-1.19.patch"
  ];
  upstreamGo = pkgs.go_1_26.overrideAttrs (old: {
    patches = builtins.filter (
      patch:
      !pkgs.lib.any (
        suffix: pkgs.lib.hasSuffix suffix (builtins.baseNameOf (toString patch))
      ) nixRuntimePatchSuffixes
    ) old.patches;
  });
  buildGoModule = pkgs.buildGoModule.override { go = upstreamGo; };
  cgoEnv = {
    CGO_ENABLED = "1";
    NIX_DONT_SET_RPATH = "1";
  }
  // commonEnv;
  cgoBase = {
    env = cgoEnv;
  };

  common = {
    version = "0";
    src = pkgs.lib.cleanSource ../tinfoil;
    vendorHash = "sha256-KJqkXS1sE+l8Irev927hFgQFbwS1rQSOKYm02sA3i6Q=";
    ldflags = [
      "-s"
      "-w"
    ];
    allowedReferences = [ ];
    doCheck = false;
  };

  buildCgoCommand =
    attributes:
    buildGoModule (
      common
      // cgoBase
      // {
        ldflags = common.ldflags ++ [
          "-linkmode=external"
          "-extldflags=-Wl,--build-id=none,--dynamic-linker=/lib64/ld-linux-x86-64.so.2"
        ];
      }
      // attributes
    );

  runtime = buildCgoCommand {
    pname = "tinfoil-runtime";
    subPackages = [
      "cmd/boot"
      "cmd/containers"
      "cmd/egress"
      "cmd/pid1"
      "cmd/shim"
    ];
    postInstall = ''
      for command in boot containers egress pid1 shim; do
        mv "$out/bin/$command" "$out/bin/tinfoil-$command"
      done
    '';
  };

  debugPID1 = buildCgoCommand {
    pname = "tinfoil-debug-pid1";
    subPackages = [ "cmd/pid1" ];
    tags = [ "tinfoil_debug_image" ];
    postInstall = ''
      mv "$out/bin/pid1" "$out/bin/tinfoil-pid1"
    '';
  };

  initrd = buildGoModule (
    common
    // {
      pname = "tinfoil-initrd";
      subPackages = [ "cmd/initrd" ];
      env = commonEnv // {
        CGO_ENABLED = "0";
      };
      postInstall = ''
        mv "$out/bin/initrd" "$out/bin/tinfoil-initrd"
      '';
    }
  );

  checkSource = pkgs.lib.fileset.toSource {
    root = ../.;
    fileset = pkgs.lib.fileset.unions [
      ../image
      ../repart.d
      ../tinfoil
    ];
  };

  checks = buildGoModule {
    pname = "tinfoil-checks";
    version = "0";
    src = checkSource;
    sourceRoot = "source/tinfoil";
    inherit (common) vendorHash;
    inherit (cgoBase) env;
    doCheck = true;
    buildPhase = "true";
    checkPhase = ''
      runHook preCheck
      go test ./...
      go test -race ./cmd/pid1 ./internal/boot/... ./internal/nvml
      go test -tags=tinfoil_debug_image ./cmd/pid1
      go vet ./...
      runHook postCheck
    '';
    installPhase = "touch $out";
  };
in
{
  inherit checks;
  packages = {
    "debug-pid1" = debugPID1;
    "runtime-go" = runtime;
    "tinfoil-initrd" = initrd;
  };
}

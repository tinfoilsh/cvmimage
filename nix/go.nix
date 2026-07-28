{ pkgs }:

let
  commonEnv.GOTOOLCHAIN = "local";

  nixRuntimePatchSuffixes = [
    "iana-etc-1.25.patch"
    "mailcap-1.17.patch"
    "tzdata-1.19.patch"
  ];
  upstreamGo = pkgs.go_1_25.overrideAttrs (old: {
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
    # go-nvml leaves NVML symbols unresolved until the measured NVIDIA
    # library is available in the guest. BIND_NOW resolves them before
    # main and makes CPU-only boot fail with a symbol lookup error.
    hardeningDisable = [ "bindnow" ];
  };

  common = {
    version = "0";
    src = pkgs.lib.cleanSource ../tinfoil;
    vendorHash = "sha256-gQi1zu60GGk89+RWnafiZ1Wqu0DR5N2uX1UbYTjqRHM=";
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
      "cmd/container-status"
      "cmd/egress"
      "cmd/init"
      "cmd/shim"
    ];
    postInstall = ''
      for command in boot container-status egress init shim; do
        mv "$out/bin/$command" "$out/bin/tinfoil-$command"
      done
    '';
  };

  debugInit = buildCgoCommand {
    pname = "tinfoil-debug-init";
    subPackages = [ "cmd/init" ];
    tags = [ "tinfoil_debug_image" ];
    postInstall = ''
      mv "$out/bin/init" "$out/bin/tinfoil-init"
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
    inherit (cgoBase) env hardeningDisable;
    doCheck = true;
    buildPhase = "true";
    checkPhase = ''
      runHook preCheck
      go test ./...
      go test -race ./cmd/init ./internal/boot/...
      go test -tags=tinfoil_debug_image ./cmd/init
      go vet ./...
      runHook postCheck
    '';
    installPhase = "touch $out";
  };
in
{
  inherit checks upstreamGo;
  packages = {
    "debug-init" = debugInit;
    "runtime-go" = runtime;
    "tinfoil-initrd" = initrd;
  };
}

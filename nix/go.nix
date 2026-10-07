{ pkgs }:

let
  commonEnv.GOTOOLCHAIN = "local";

  nixRuntimePatchSuffixes = [
    "iana-etc-1.25.patch"
    "mailcap-1.17.patch"
    "tzdata-1.19.patch"
  ];
  upstreamGo = pkgs.go_1_27.overrideAttrs (old: {
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
    src = pkgs.lib.fileset.toSource {
      root = ../.;
      fileset = pkgs.lib.fileset.unions [
        ../config
        ../tinfoil
      ];
    };
    sourceRoot = "source/tinfoil";
    vendorHash = "sha256-mzjXyg5h4Nl/8jcu/lwGQYSIinQX7mIyjU/gl2Sev6Q=";
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
      "cmd/volumeworker"
    ];
    postInstall = ''
      for command in boot containers egress pid1 shim; do
        mv "$out/bin/$command" "$out/bin/tinfoil-$command"
      done
      mv "$out/bin/volumeworker" "$out/bin/tinfoil-volume-worker"
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
      ../config
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

  configCommon = {
    inherit (common) version ldflags allowedReferences;
    src = pkgs.lib.cleanSource ../config;
    vendorHash = "sha256-qT4/QJcg/q/+9INK8e9Q94QezYlrBouwviAXi5yS0vM=";
    env = commonEnv // {
      CGO_ENABLED = "0";
    };
  };

  configValidator = buildGoModule (configCommon // {
    pname = "tinfoil-config";
    subPackages = [ "cmd/tinfoil-config" ];
    doCheck = false;
  });

  configChecks = buildGoModule (configCommon // {
    pname = "tinfoil-config-checks";
    doCheck = true;
    buildPhase = "true";
    checkPhase = ''
      runHook preCheck
      go test ./...
      go vet ./...
      runHook postCheck
    '';
    installPhase = "touch $out";
  });
in
{
  inherit checks;
  packages = {
    "config-checks" = configChecks;
    "config-validator" = configValidator;
    "debug-pid1" = debugPID1;
    "runtime-go" = runtime;
    "tinfoil-initrd" = initrd;
  };
}

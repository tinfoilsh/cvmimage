{ pkgs, gpuSupport }:

let
  commonEnv.GOTOOLCHAIN = "local";

  nixRuntimePatchSuffixes = [
    "iana-etc-1.25.patch"
    "mailcap-1.17.patch"
    "tzdata-1.19.patch"
  ];
  # Pin the Go toolchain explicitly; bump this together with the src hash
  # whenever the toolchain needs an update.
  upstreamGo = pkgs.go_1_27.overrideAttrs (old: {
    version = "1.27.3";
    src = pkgs.fetchurl {
      url = "https://go.dev/dl/go1.27.3.src.tar.gz";
      hash = "sha256-bndJA1zzYPBrJXXRYup535/ajvZxiJ5cN1+OUHd/Jrs=";
    };
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
    env = if gpuSupport then cgoEnv else commonEnv // { CGO_ENABLED = "0"; };
  };

  common = {
    version = "0";
    src = pkgs.lib.cleanSource ../tinfoil;
    vendorHash = "sha256-9UgRJxssmYL1e7Eez2OHI8Q5fXrKtI1S2kHjfQ9iJj0=";
    ldflags = [
      "-s"
      "-w"
    ];
    tags = pkgs.lib.optional gpuSupport "tinfoil_gpu";
    allowedReferences = [ ];
    doCheck = false;
  };

  buildCgoCommand =
    attributes:
    buildGoModule (
      common
      // cgoBase
      // {
        ldflags = common.ldflags ++ pkgs.lib.optionals gpuSupport [
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
    tags = common.tags ++ [ "tinfoil_debug_image" ];
    postInstall = ''
      mv "$out/bin/pid1" "$out/bin/tinfoil-pid1"
    '';
  };

  initrd = buildGoModule (
    common
    // {
      pname = "tinfoil-initrd";
      subPackages = [ "cmd/initrd" ];
      tags = [ ];
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
    env = cgoEnv;
    doCheck = true;
    buildPhase = "true";
    checkPhase = ''
      runHook preCheck
      for tags in "" tinfoil_gpu; do
        go test -tags="$tags" ./...
        go test -race -tags="$tags" ./cmd/pid1 ./internal/boot/...
        go test -tags="tinfoil_debug_image,$tags" ./cmd/pid1
        go vet -tags="$tags" ./...
      done
      go test -race -tags=tinfoil_gpu ./internal/nvml
      if go list -deps ./cmd/... | grep -E '/(nvml|nvidia)$'; then
        echo "CPU runtime includes GPU dependencies" >&2
        exit 1
      fi
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

{ pkgs }:

let
  commonEnv = {
    GOTOOLCHAIN = "local";
    GOWORK = "off";
  };

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
    ldflags = [
      "-s"
      "-w"
    ];
    allowedReferences = [ ];
    doCheck = false;
  };

  buildCgoCommand =
    module: attributes:
    buildGoModule (
      common
      // module
      // cgoBase
      // {
        ldflags = common.ldflags ++ [
          "-linkmode=external"
          "-extldflags=-Wl,--build-id=none,--dynamic-linker=/lib64/ld-linux-x86-64.so.2"
        ];
      }
      // attributes
    );

  runtime =
    module: commands:
    buildCgoCommand module {
      pname = "tinfoil-runtime";
      subPackages = map (command: "cmd/${command}") commands;
      postInstall = ''
        for command in "$out"/bin/*; do
          mv "$command" "$out/bin/tinfoil-$(basename "$command")"
        done
      '';
    };

  debugPID1 =
    module:
    buildCgoCommand module {
      pname = "tinfoil-debug-pid1";
      subPackages = [ "cmd/pid1" ];
      tags = [ "tinfoil_debug_image" ];
      postInstall = ''
        mv "$out/bin/pid1" "$out/bin/tinfoil-pid1"
      '';
    };

  initrd =
    module:
    buildGoModule (
      common
      // module
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

  checks =
    {
      name,
      module,
      extraChecks ? "",
      forbiddenDependencies ? [ ],
    }:
    buildGoModule (
      module
      // {
        pname = name;
        version = "0";
        inherit (cgoBase) env;
        doCheck = true;
        buildPhase = "true";
        checkPhase = ''
          runHook preCheck
          ${pkgs.lib.optionalString (forbiddenDependencies != [ ]) ''
            for tags in "" tinfoil_debug_image; do
              go list -deps -test -tags="$tags" -f '{{.ImportPath}}' ./... > dependencies.txt
              while IFS= read -r dependency; do
                for forbidden in ${pkgs.lib.escapeShellArgs forbiddenDependencies}; do
                  case "$dependency" in
                    "$forbidden"|"$forbidden"/*)
                      echo "${name}: forbidden dependency $dependency (tags=$tags)" >&2
                      exit 1
                      ;;
                  esac
                done
              done < dependencies.txt
            done
          ''}
          go test ./...
          ${extraChecks}
          go vet ./...
          runHook postCheck
        '';
        installPhase = "touch $out";
      }
    );
  fileset =
    directory:
    pkgs.lib.fileset.fileFilter (
      file: file.hasExt "go" || file.hasExt "mod" || file.hasExt "sum"
    ) directory;
  source =
    directories:
    pkgs.lib.fileset.toSource {
      root = ../.;
      fileset = pkgs.lib.fileset.unions (map fileset directories);
    };
in
{
  inherit
    runtime
    debugPID1
    initrd
    checks
    source
    fileset
    ;
}

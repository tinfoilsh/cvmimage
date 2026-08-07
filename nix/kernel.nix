{
  pkgs,
  debugConsole ? false,
}:

let
  inherit (pkgs) lib;

  version = "7.0.0";
  release = "7.0.0-28-generic";
  buildTimestamp = "Tue Jan  1 00:00:00 UTC 1980";
  policyConfigs = [
    ../kernel/config.d/10-tinfoil-cvm-policy.config
    ../kernel/config.d/20-console-common.config
  ] ++ [
    (if debugConsole then
      ../kernel/config.d/20-debug-console.config
    else
      ../kernel/config.d/20-production-console.config)
  ];
  policyConfigArgs = lib.concatMapStringsSep " " (path: "${path}") policyConfigs;

  sourceDeb = pkgs.fetchurl {
    url = "https://snapshot.ubuntu.com/ubuntu/20260721T000000Z/pool/main/l/linux/linux-source-7.0.0_7.0.0-28.28_all.deb";
    hash = "sha256-3VmUsZmhywax8za7CGxcI6klj9z9y7fcyNOvqaXZLhM=";
  };

  source =
    pkgs.runCommand "linux-source-7.0.0-28.28"
      {
        nativeBuildInputs = [
          pkgs.dpkg
          pkgs.gnutar
          pkgs.xz
        ];
      }
      ''
        mkdir unpack "$out"
        dpkg-deb -x ${sourceDeb} unpack
        source_tarball=$(find unpack/usr/src/linux-source-${version} \
          -maxdepth 1 -type f -name 'linux-source-*.tar.*' -print -quit)
        test -n "$source_tarball"
        tar -xf "$source_tarball" \
          --strip-components=1 -C "$out"
      '';

  patchedSource = pkgs.applyPatches {
    name = "linux-source-${version}-tinfoil";
    src = source;
    patches = [ ./patches/kernel-disable-virtio-pci-admin-legacy.patch ];
  };

  configFile = pkgs.stdenv.mkDerivation {
    pname = "tinfoil-linux-config";
    inherit version;
    src = patchedSource;
    nativeBuildInputs = [
      pkgs.bash
      pkgs.bison
      pkgs.flex
      pkgs.gawk
      pkgs.gnumake
      pkgs.pahole
      pkgs.pkg-config
    ];
    dontConfigure = true;
    buildPhase = ''
      runHook preBuild
      install -Dm0644 ${../kernel/tinfoil-cvm-7.0.defconfig} \
        arch/x86/configs/tinfoil_cvm_defconfig
      make KERNELVERSION=${version} tinfoil_cvm_defconfig
      scripts/kconfig/merge_config.sh -m \
        .config ${policyConfigArgs}
      make KERNELVERSION=${version} olddefconfig
      ${pkgs.bash}/bin/bash ${../kernel/check-config.sh} \
        .config ${policyConfigArgs}
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      install -Dm0644 .config "$out"
      runHook postInstall
    '';
  };

  uncheckedKernel = pkgs.linuxManualConfig {
    pname = "tinfoil-linux";
    inherit version;
    src = patchedSource;
    configfile = configFile;
    config = {
      CONFIG_MODULES = "y";
      CONFIG_RUST = "n";
    };
    modDirVersion = release;
    kernelPatches = [
      {
        name = "disable-build-id";
        patch = ./patches/kernel-disable-build-id.patch;
      }
      {
        name = "gate-efi-smbios-on-dmi";
        patch = ./patches/kernel-gate-efi-smbios-on-dmi.patch;
      }
    ];
    extraMakeFlags = [
      "KBUILD_BUILD_USER=tinfoil"
      "KBUILD_BUILD_HOST=tinfoil-builder"
      "KERNELVERSION=${version}"
    ];
  };

  kernel = uncheckedKernel.overrideAttrs (old: {
    buildFlags =
      builtins.filter (flag: !(lib.hasPrefix "KBUILD_BUILD_VERSION=" flag)) (old.buildFlags or [ ])
      ++ [
        "KBUILD_BUILD_VERSION=1"
      ];
    preBuild = (old.preBuild or "") + ''
      export KBUILD_BUILD_TIMESTAMP='${buildTimestamp}'
      export KCFLAGS="''${KCFLAGS:-} -ffile-prefix-map=$buildRoot=/build -fmacro-prefix-map=$buildRoot=/build -fdebug-prefix-map=$buildRoot=/build"
      export KAFLAGS="''${KAFLAGS:-} -Wa,--debug-prefix-map=$buildRoot=/build"
    '';
    postInstall = (old.postInstall or "") + ''
      find "$dev/lib/modules/${release}/build" -type f -name '*.cmd' \
        -exec sed -i "s|$buildRoot|/build|g" {} +
    '';
    postConfigure = (old.postConfigure or "") + ''
      ${pkgs.bash}/bin/bash ${../kernel/check-config.sh} \
        "$buildRoot/.config" ${policyConfigArgs}
    '';
  });

  artifacts =
    pkgs.runCommand "tinfoil-kernel-${release}-artifacts"
      {
        allowedReferences = [ ];
        nativeBuildInputs = [ pkgs.coreutils ];
      }
      ''
        mkdir "$out"
        install -m0644 ${kernel}/bzImage "$out/tinfoil-custom.vmlinuz"
        install -m0644 ${kernel.dev}/lib/modules/${release}/build/.config "$out/config"
        install -m0644 ${kernel.dev}/lib/modules/${release}/build/Module.symvers "$out/Module.symvers"
        install -m0644 ${kernel.modules}/lib/modules/${release}/modules.builtin "$out/modules.builtin"
        printf '%s\n' '${release}' > "$out/kernel.release"
        (cd "$out" && sha256sum \
          tinfoil-custom.vmlinuz config Module.symvers modules.builtin kernel.release \
          > checksums.sha256)
      '';
in
{
  inherit artifacts release;
  kernelPackages = pkgs.linuxPackagesFor kernel;
}

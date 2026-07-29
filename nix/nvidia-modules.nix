{ pkgs, kernel }:

let
  inherit (pkgs) lib;
  inherit (kernel) kernelPackages release;
  version = "595.71.05";

  _versionCheck =
    assert kernelPackages.nvidiaPackages.production.version == version;
    true;
  kernelSource = "${kernelPackages.kernel.dev}/lib/modules/${release}/source";
  nvidiaOpen = kernelPackages.nvidiaPackages.production.open.overrideAttrs (old: {
    env = (old.env or { }) // {
      CONFIG_X86_KERNEL_IBT = "";
      KBUILD_BUILD_TIMESTAMP = "Tue Jan  1 00:00:00 UTC 1980";
      NV_EXCLUDE_KERNEL_MODULES = "nvidia-drm nvidia-peermem";
      NV_BUILD_HOST = "tinfoil-builder";
      NV_BUILD_USER = "tinfoil";
      KCFLAGS = "-ffile-prefix-map=${kernelSource}=/usr/src/linux -fmacro-prefix-map=${kernelSource}=/usr/src/linux -fdebug-prefix-map=${kernelSource}=/usr/src/linux";
    };
    makeFlags = builtins.filter (flag: !(lib.hasPrefix "KBUILD_BUILD_TIMESTAMP=" flag)) (
      old.makeFlags or [ ]
    );
  });

  modules =
    assert _versionCheck;
    pkgs.runCommand "tinfoil-nvidia-open-${version}-${release}"
      {
        nativeBuildInputs = [
          pkgs.coreutils
          pkgs.kmod
        ];
        # The measured modules must not depend on the Nix store. Symbol CRC
        # compatibility with the custom kernel is enforced authoritatively by
        # CONFIG_MODVERSIONS when the qualified image loads the modules.
        allowedReferences = [ ];
      }
      ''
        module_dir=${nvidiaOpen}/lib/modules/${release}/kernel/drivers/video
        expected_modules=(nvidia-modeset.ko nvidia-uvm.ko nvidia.ko)

        mkdir "$out"
        for module in "''${expected_modules[@]}"; do
          install -m0644 "$module_dir/$module" "$out/$module"
        done

        expected_vermagic='${release} SMP preempt mod_unload modversions '

        {
          printf 'version=%s\n' '${version}'
          printf 'release=%s\n' '${release}'
          printf 'vermagic=%s\n' "$expected_vermagic"
        } > "$out/validation.txt"

        for module in "''${expected_modules[@]}"; do
          module_path="$out/$module"
          actual_version=$(modinfo -F version "$module_path")
          actual_vermagic=$(modinfo -F vermagic "$module_path")
          case "$module" in
            nvidia.ko) expected_depends= ;;
            *) expected_depends='nvidia' ;;
          esac
          actual_depends=$(modinfo -F depends "$module_path")

          test "$actual_version" = '${version}'
          test "$actual_vermagic" = "$expected_vermagic"
          test "$actual_depends" = "$expected_depends"

          printf '%s depends=%s\n' "$module" "$actual_depends" \
            >> "$out/validation.txt"
        done

        (cd "$out" && sha256sum "''${expected_modules[@]}" > checksums.sha256)
      '';
in
{
  inherit modules;
}

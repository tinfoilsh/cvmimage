{ pkgs, kernel }:

let
  inherit (pkgs) lib;
  inherit (kernel) kernelPackages release;
  version = "595.71.05";

  _versionCheck =
    assert kernelPackages.nvidiaPackages.production.version == version;
    true;
  nvidiaOpen = kernelPackages.nvidiaPackages.production.open.overrideAttrs (old: {
    env = (old.env or { }) // {
      CONFIG_X86_KERNEL_IBT = "";
      KBUILD_BUILD_TIMESTAMP = "Tue Jan  1 00:00:00 UTC 1980";
      NV_EXCLUDE_KERNEL_MODULES = "nvidia-drm nvidia-peermem";
      NV_BUILD_HOST = "tinfoil-builder";
      NV_BUILD_USER = "tinfoil";
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
          pkgs.binutils
          pkgs.coreutils
          pkgs.diffutils
          pkgs.findutils
          pkgs.gawk
          pkgs.gnugrep
          pkgs.kmod
        ];
      }
      ''
        source_root=${nvidiaOpen}/lib/modules/${release}
        mapfile -t built_modules < <(find "$source_root" -type f -name '*.ko' -printf '%f\n' | sort)
        expected_modules=(nvidia-modeset.ko nvidia-uvm.ko nvidia.ko)

        if ! diff -u \
          <(printf '%s\n' "''${expected_modules[@]}") \
          <(printf '%s\n' "''${built_modules[@]}"); then
          echo "NVIDIA build produced an unexpected module set" >&2
          exit 1
        fi

        mkdir "$out"
        for module in "''${expected_modules[@]}"; do
          source=$(find "$source_root" -type f -name "$module" -print -quit)
          test -n "$source"
          install -m0644 "$source" "$out/$module"
        done

        expected_vermagic='${release} SMP preempt mod_unload modversions '
        : > kernel-crcs
        awk '{ print $2, tolower($1) }' ${kernel.artifacts}/Module.symvers \
          | sort -u > kernel-crcs
        : > selected-crcs
        for module in "$out"/*.ko; do
          for section in __kcrctab __kcrctab_gpl; do
            section_index=$(readelf -SW "$module" \
              | sed -n "s/^ *\[ *\([0-9][0-9]*\)\] $section .*/\1/p")
            test -n "$section_index" || continue
            section_file=$(mktemp)
            objcopy --dump-section "$section=$section_file" "$module" /dev/null
            while read -r offset symbol; do
              crc=$(od -An -tx4 -N4 -j "$((16#$offset))" "$section_file" \
                | tr -d '[:space:]')
              printf '%s 0x%s\n' "''${symbol#__crc_}" "$crc"
            done < <(readelf -sW "$module" \
              | awk -v section_index="$section_index" \
                '$7 == section_index && $8 ~ /^__crc_/ { print $2, $8 }')
            rm -f "$section_file"
          done
        done | sort -u > selected-crcs

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

          kernel_imports=0
          selected_imports=0
          while read -r imported_crc symbol; do
            imported_crc=$(printf '%s' "$imported_crc" | tr '[:upper:]' '[:lower:]')
            kernel_crc=$(awk -v symbol="$symbol" '$1 == symbol { print $2 }' kernel-crcs)
            if test -n "$kernel_crc"; then
              test "$imported_crc" = "$kernel_crc"
              kernel_imports=$((kernel_imports + 1))
            else
              selected_crc=$(awk -v symbol="$symbol" '$1 == symbol { print $2 }' selected-crcs)
              if test -n "$selected_crc"; then
                if test "$imported_crc" != "$selected_crc"; then
                  echo "$module imports $symbol with CRC $imported_crc, selected module exports $selected_crc" >&2
                  exit 1
                fi
                selected_imports=$((selected_imports + 1))
              else
                echo "$module imports unprovided symbol $symbol" >&2
                exit 1
              fi
            fi
          done < <(modprobe --dump-modversions "$module_path")

          printf '%s kernel_imports=%s selected_module_imports=%s depends=%s\n' \
            "$module" "$kernel_imports" "$selected_imports" "$actual_depends" \
            >> "$out/validation.txt"
        done

        (cd "$out" && sha256sum "''${expected_modules[@]}" > checksums.sha256)
      '';
in
{
  inherit nvidiaOpen modules;
  inherit version;
}

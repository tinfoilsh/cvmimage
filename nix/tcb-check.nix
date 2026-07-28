{
  pkgs,
  rootfs,
  initrd,
}:

pkgs.runCommand "tinfoil-tcb-check"
  {
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.cpio
      pkgs.diffutils
      pkgs.gnugrep
      pkgs.gnutar
      pkgs.zstd
    ];
  }
  ''
    set -Eeuo pipefail

    tar -tf ${rootfs} | sort > rootfs.list
    forbidden_patterns=(
      '^\./usr/bin/debconf($|/)'
      '^\./usr/share/debconf($|/)'
      '^\./usr/share/doc/debconf($|/)'
      '^\./usr/sbin/dpkg-reconfigure$'
      '^\./sbin/(capsh|getcap|getpcaps|setcap)$'
      '^\./usr/sbin/(capsh|getcap|getpcaps|setcap)$'
    )
    for pattern in "''${forbidden_patterns[@]}"; do
      if grep -E "$pattern" rootfs.list; then
        echo "forbidden rootfs payload matched: $pattern" >&2
        exit 1
      fi
    done

    required_rootfs_paths=(
      './etc/ca-certificates.conf'
      './etc/ssl/certs/ca-certificates.crt'
      './usr/bin/tinfoil-boot'
      './usr/bin/tinfoil-container-status'
      './usr/bin/tinfoil-egress'
      './usr/bin/tinfoil-init'
      './usr/bin/tinfoil-shim'
      './usr/lib/tinfoil/kernel-modules/nvidia.ko'
      './usr/lib/tinfoil/kernel-modules/nvidia-uvm.ko'
      './usr/lib/tinfoil/kernel-modules/nvidia-modeset.ko'
    )
    for path in "''${required_rootfs_paths[@]}"; do
      grep -Fxq "$path" rootfs.list
    done

    zstd -dc ${initrd} | cpio -t --quiet | sort > initrd.list
    cat > expected-initrd.list <<'EOF'
dev
init
proc
run
sys
usr
usr/bin
usr/bin/tinfoil-initrd
EOF
    diff -u expected-initrd.list initrd.list

    touch "$out"
  ''

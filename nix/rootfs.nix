{
  pkgs,
  runtimeGo,
  debugInit,
  nvattest,
  nvidiaModules,
}:

let
  lock = builtins.fromJSON (builtins.readFile ../image/runtime-packages.lock.json);
  sources = import ./runtime-sources.nix;

  fetchDeb = package: pkgs.fetchurl {
    name = "${package.name}.deb";
    urls = package.urls or [ package.url ];
    sha256 = package.sha256;
  };

  ubuntuDebs = map fetchDeb lock.packages;
  nvidiaDebs = map fetchDeb sources.nvidiaDebs;
  busyboxDeb = fetchDeb sources.busybox;
  dockerArchive = pkgs.fetchurl {
    inherit (sources.docker) name url;
    sha256 = sources.docker.sha256;
  };

  repositoryFiles = [
    { source = ../image/rootfs/etc/.pwd.lock; target = "etc/.pwd.lock"; mode = "0600"; }
    { source = ../image/rootfs/etc/containerd/config.toml; target = "etc/containerd/config.toml"; mode = "0644"; }
    { source = ../image/rootfs/etc/docker/daemon.json; target = "etc/docker/daemon.json"; mode = "0644"; }
    { source = ../image/rootfs/etc/group; target = "etc/group"; mode = "0644"; }
    { source = ../image/rootfs/etc/gshadow; target = "etc/gshadow"; mode = "0640"; }
    { source = ../image/rootfs/etc/hostname; target = "etc/hostname"; mode = "0644"; }
    { source = ../image/rootfs/etc/hosts; target = "etc/hosts"; mode = "0644"; }
    { source = ../image/rootfs/etc/nsswitch.conf; target = "etc/nsswitch.conf"; mode = "0644"; }
    { source = ../image/rootfs/etc/nvidia-container-runtime/config.toml; target = "etc/nvidia-container-runtime/config.toml"; mode = "0644"; }
    { source = ../image/rootfs/etc/passwd; target = "etc/passwd"; mode = "0644"; }
    { source = ../image/rootfs/etc/resolv.conf; target = "etc/resolv.conf"; mode = "0644"; }
    { source = ../image/rootfs/etc/shadow; target = "etc/shadow"; mode = "0640"; }
    { source = ../image/rootfs/etc/systemd/system-preset/00-tinfoil.preset; target = "etc/systemd/system-preset/00-tinfoil.preset"; mode = "0644"; }
    { source = ../image/rootfs/usr/lib/clock-epoch; target = "usr/lib/clock-epoch"; mode = "0644"; }
    { source = ../image/rootfs/usr/lib/os-release; target = "usr/lib/os-release"; mode = "0644"; }
  ];

  repositoryReplacements = [
    { source = ../image/rootfs/etc/nftables.conf; target = "etc/nftables.conf"; mode = "0644"; }
    { source = ../image/rootfs/usr/share/nvidia/nvswitch/fabricmanager.cfg; target = "usr/share/nvidia/nvswitch/fabricmanager.cfg"; mode = "0644"; }
  ];

  extractDebs = pkgs.lib.concatMapStringsSep "\n" (deb: ''
    ${pkgs.dpkg}/bin/dpkg-deb --fsys-tarfile ${deb} |
      ${pkgs.gnutar}/bin/tar --extract --file=- --directory "$root" \
        --no-same-owner --keep-old-files
  '') (ubuntuDebs ++ nvidiaDebs);

  repositoryInstalls = pkgs.lib.concatMapStringsSep "\n" (file: ''
    test ! -e "$root/${file.target}"
    test ! -L "$root/${file.target}"
    install -D -m ${file.mode} ${file.source} "$root/${file.target}"
  '') repositoryFiles;

  repositoryReplacementInstalls = pkgs.lib.concatMapStringsSep "\n" (file: ''
    install -D -m ${file.mode} ${file.source} "$root/${file.target}"
  '') repositoryReplacements;

  moduleInstalls = pkgs.lib.concatMapStringsSep "\n" (module: ''
    test ! -e "$root/usr/lib/tinfoil/kernel-modules/${builtins.baseNameOf module}"
    test ! -L "$root/usr/lib/tinfoil/kernel-modules/${builtins.baseNameOf module}"
    install -m 0644 ${module} \
      "$root/usr/lib/tinfoil/kernel-modules/${builtins.baseNameOf module}"
  '') nvidiaModules;

  deterministicTar = root: output: ''
    ${pkgs.gnutar}/bin/tar --create --file ${output} --directory ${root} \
      --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
      --format=gnu .
  '';

  rootfs = pkgs.runCommand "cvmimage-rootfs.tar" {
    allowedReferences = [ ];
    nativeBuildInputs = [ pkgs.coreutils pkgs.findutils pkgs.gnutar ];
  } ''
    set -o pipefail
    root="$TMPDIR/root"
    mkdir -p "$root"

    ${extractDebs}
    chmod 0755 "$root"

    docker="$TMPDIR/docker"
    mkdir -p "$docker" "$root/usr/bin"
    ${pkgs.gnutar}/bin/tar --extract --gzip --file ${dockerArchive} \
      --directory "$docker" --strip-components=1
    for command in containerd containerd-shim-runc-v2 dockerd runc; do
      test ! -e "$root/usr/bin/$command"
      test ! -L "$root/usr/bin/$command"
      install -m 0755 "$docker/$command" "$root/usr/bin/$command"
    done

    for command in boot container-status egress init shim; do
      test ! -e "$root/usr/bin/tinfoil-$command"
      test ! -L "$root/usr/bin/tinfoil-$command"
      install -m 0755 ${runtimeGo}/bin/tinfoil-$command \
        "$root/usr/bin/tinfoil-$command"
    done

    test ! -e "$root/usr/bin/nvattest"
    test ! -L "$root/usr/bin/nvattest"
    test ! -e "$root/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2"
    test ! -L "$root/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2"
    install -D -m 0755 ${nvattest}/usr/bin/nvattest "$root/usr/bin/nvattest"
    install -D -m 0644 ${nvattest}/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2 \
      "$root/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2"
    test ! -e "$root/usr/lib/x86_64-linux-gnu/libnvat.so.1"
    test ! -L "$root/usr/lib/x86_64-linux-gnu/libnvat.so.1"
    ln -s libnvat.so.1.2.2 \
      "$root/usr/lib/x86_64-linux-gnu/libnvat.so.1"

    mkdir -p "$root/usr/lib/tinfoil/kernel-modules"
    ${moduleInstalls}

    ${repositoryInstalls}
    ${repositoryReplacementInstalls}
    chmod 0755 "$root"

    mkdir -p "$root/dev" "$root/mnt/ramdisk" "$root/proc" "$root/run" \
      "$root/sys" "$root/tmp" "$root/var/tmp" "$root/usr/lib64" \
      "$root/etc/ssl/certs"
    chmod 0755 "$root" "$root/dev" "$root/mnt" "$root/mnt/ramdisk" \
      "$root/proc" "$root/run" "$root/sys" "$root/tmp" "$root/var" \
      "$root/var/tmp"

    ln -s usr/lib64 "$root/lib64"
    ln -s usr/sbin "$root/sbin"
    ln -s ../run "$root/var/run"

    find "$root/usr/share/ca-certificates" -type f -name '*.crt' -print0 |
      sort -z |
      xargs -0 cat > "$root/etc/ssl/certs/ca-certificates.crt"
    chmod 0644 "$root/etc/ssl/certs/ca-certificates.crt"

    ${deterministicTar "$root" "$out"}
  '';

  debugLayer = pkgs.runCommand "cvmimage-debug-layer.tar" {
    allowedReferences = [ ];
    nativeBuildInputs = [ pkgs.coreutils pkgs.gnutar ];
  } ''
    set -o pipefail
    root="$TMPDIR/root"
    mkdir -p "$root"
    ${pkgs.dpkg}/bin/dpkg-deb --fsys-tarfile ${busyboxDeb} |
      ${pkgs.gnutar}/bin/tar --extract --file=- --directory "$root" \
        --no-same-owner --no-overwrite-dir
    test ! -e "$root/usr/bin/tinfoil-init"
    test ! -L "$root/usr/bin/tinfoil-init"
    install -D -m 0755 ${debugInit}/bin/tinfoil-init \
      "$root/usr/bin/tinfoil-init"
    install -d -m 0700 "$root/root"
    ${deterministicTar "$root" "$out"}
  '';
in
{
  inherit rootfs debugLayer;
}

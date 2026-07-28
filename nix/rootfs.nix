{
  pkgs,
  ubuntuDebs,
  runtimeGo,
  debugInit,
  nvattest,
  nvidiaModules,
}:

let
  sources = import ./runtime-sources.nix;

  fetchDeb = package: pkgs.fetchurl {
    name = "${package.name}.deb";
    urls = package.urls or [ package.url ];
    sha256 = package.sha256;
  };

  nvidiaDebs = map fetchDeb sources.nvidiaDebs;
  busyboxDeb = fetchDeb sources.busybox;
  dockerArchive = pkgs.fetchurl {
    inherit (sources.docker) name url;
    sha256 = sources.docker.sha256;
  };
  matchesDebPackage = package: deb:
    builtins.match ".*-${package}_[^/]+[.]deb"
      (builtins.baseNameOf (toString deb)) != null;
  caCertificatesDeb =
    pkgs.lib.findFirst (matchesDebPackage "ca-certificates")
      (throw "ca-certificates deb missing from runtime package closure")
      ubuntuDebs;
  provenanceOnlyUbuntuPackages = [
    "debconf"
    "libcap2-bin"
  ];
  isProvenanceOnlyDeb = deb:
    pkgs.lib.any (package: matchesDebPackage package deb)
      provenanceOnlyUbuntuPackages;
  runtimeUbuntuDebs = pkgs.lib.filter (deb: !(isProvenanceOnlyDeb deb)) ubuntuDebs;

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
  '') (runtimeUbuntuDebs ++ nvidiaDebs);

  repositoryInstalls = pkgs.lib.concatMapStringsSep "\n" (file: ''
    install_new ${file.mode} ${file.source} "$root/${file.target}" -D
  '') repositoryFiles;

  repositoryReplacementInstalls = pkgs.lib.concatMapStringsSep "\n" (file: ''
    install -D -m ${file.mode} ${file.source} "$root/${file.target}"
  '') repositoryReplacements;

  moduleInstalls = pkgs.lib.concatMapStringsSep "\n" (module: ''
    install_new 0644 ${module} \
      "$root/usr/lib/tinfoil/kernel-modules/${builtins.baseNameOf module}"
  '') nvidiaModules;

  shellInstallHelpers = ''
    install_new() {
      mode="$1"
      source="$2"
      target="$3"
      shift 3
      test ! -e "$target"
      test ! -L "$target"
      install "$@" -m "$mode" "$source" "$target"
    }

    link_new() {
      source="$1"
      target="$2"
      test ! -e "$target"
      test ! -L "$target"
      ln -s "$source" "$target"
    }
  '';

  deterministicTar = root: output: ''
    ${pkgs.gnutar}/bin/tar --create --file ${output} --directory ${root} \
      --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
      --format=gnu .
  '';

  rootfs = pkgs.runCommand "cvmimage-rootfs.tar" {
    allowedReferences = [ ];
    nativeBuildInputs = [ pkgs.coreutils pkgs.findutils pkgs.gnused pkgs.gnutar ];
  } ''
    set -o pipefail
    root="$TMPDIR/root"
    mkdir -p "$root"
    ${shellInstallHelpers}

    ${extractDebs}
    chmod 0755 "$root"

    docker="$TMPDIR/docker"
    mkdir -p "$docker" "$root/usr/bin"
    ${pkgs.gnutar}/bin/tar --extract --gzip --file ${dockerArchive} \
      --directory "$docker" --strip-components=1
    for command in containerd containerd-shim-runc-v2 dockerd runc; do
      install_new 0755 "$docker/$command" "$root/usr/bin/$command"
    done

    for command in boot container-status egress init shim; do
      install_new 0755 ${runtimeGo}/bin/tinfoil-$command \
        "$root/usr/bin/tinfoil-$command"
    done

    install_new 0755 ${nvattest}/usr/bin/nvattest "$root/usr/bin/nvattest" -D
    install_new 0644 ${nvattest}/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2 \
      "$root/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2" -D
    link_new libnvat.so.1.2.2 \
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

    link_new usr/lib64 "$root/lib64"
    link_new usr/sbin "$root/sbin"
    link_new ../run "$root/var/run"

    ca_control="$TMPDIR/ca-certificates-control"
    mkdir -p "$ca_control"
    ${pkgs.dpkg}/bin/dpkg-deb --control ${caCertificatesDeb} "$ca_control"
    sed -n 's/^CERTS_LIST="\(.*\)"$/\1/p' "$ca_control/config" |
      tr ',' '\n' |
      sed -e 's/^[[:space:]]*//' -e '/^$/d' \
      > "$root/etc/ca-certificates.conf"

    bundle="$root/etc/ssl/certs/ca-certificates.crt"
    : > "$bundle"
    while IFS= read -r certificate || test -n "$certificate"; do
      case "$certificate" in
        "" | "#"*) continue ;;
        "!"*) continue ;;
      esac
      certificate_source="$root/usr/share/ca-certificates/$certificate"
      test -f "$certificate_source"
      cat "$certificate_source" >> "$bundle"
    done < "$root/etc/ca-certificates.conf"
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
    ${shellInstallHelpers}
    ${pkgs.dpkg}/bin/dpkg-deb --fsys-tarfile ${busyboxDeb} |
      ${pkgs.gnutar}/bin/tar --extract --file=- --directory "$root" \
        --no-same-owner --no-overwrite-dir
    install_new 0755 ${debugInit}/bin/tinfoil-init \
      "$root/usr/bin/tinfoil-init" -D
    install -d -m 0700 "$root/root"
    ${deterministicTar "$root" "$out"}
  '';
in
{
  inherit rootfs debugLayer;
}

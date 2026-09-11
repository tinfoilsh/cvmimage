{
  pkgs,
  go,
  platform,
}:
let
  payload = import ../nix/payload.nix { inherit pkgs; };
  sources = import ./nix/sources.nix;
  module = {
    src = go.source [
      ../tinfoil
      ./.
    ];
    modRoot = "inference";
    proxyVendor = true;
    vendorHash = "sha256-H8xwmGGzSUoxpiY88DlFzfeKP/yvOhkh+lS12GSmr+A=";
  };
  docker = payload.archiveTree {
    name = "cvmimage-docker";
    archive = pkgs.fetchurl { inherit (sources.docker) name url sha256; };
    stripComponents = 1;
  };
in
{
  basename = "tinfoilcvm";
  inherit module;
  commands = [
    "boot"
    "pid1"
    "shim"
    "containers"
    "egress"
  ];
  kernelConfigs = [ ];
  checks = go.checks {
    name = "tinfoil-inference-checks";
    forbiddenDependencies = [ "tinfoil/sandbox" ];
    module = module // {
      src = pkgs.lib.fileset.toSource {
        root = ../.;
        fileset = pkgs.lib.fileset.unions [
          (go.fileset ../tinfoil)
          (go.fileset ./.)
          ./rootfs/etc/nftables.conf
        ];
      };
    };
    extraChecks = ''
      go test -race ./internal/nvml ./internal/gpumetrics ./cmd/shim
      go test -tags=tinfoil_debug_image ./cmd/pid1
    '';
  };
  rootfs =
    { kernel }:
    let
      nvidia = import ./nix/nvidia-modules.nix { inherit pkgs kernel; };
      nvattest = (import ./nix/nvattest.nix { inherit pkgs; }).nvattest;
    in
    {
      outputs = {
        "nvidia-modules" = nvidia.modules;
        inherit nvattest;
        "runtime-package-lock" = platform.ubuntu.lock;
      };
      manifest = {
        payloads = [
          {
            archive = (payload.debTree "cvmimage-nvidia" (map payload.fetchDeb sources.nvidiaDebs)).archive;
            paths = [
              "lib/firmware/nvidia/595.71.05/gsp_ga10x.bin"
              "usr/bin/nv-fabricmanager"
              "usr/bin/nvidia-cdi-hook"
              "usr/bin/nvidia-container-runtime"
              "usr/bin/nvidia-ctk"
              "usr/bin/nvidia-persistenced"
              "usr/bin/nvidia-smi"
              "usr/lib/x86_64-linux-gnu/libcuda.so"
              "usr/lib/x86_64-linux-gnu/libcuda.so.1"
              "usr/lib/x86_64-linux-gnu/libcuda.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvfm.so.1"
              "usr/lib/x86_64-linux-gnu/libnvidia-cfg.so.1"
              "usr/lib/x86_64-linux-gnu/libnvidia-cfg.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-gpucomp.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1"
              "usr/lib/x86_64-linux-gnu/libnvidia-ml.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-nscq.so"
              "usr/lib/x86_64-linux-gnu/libnvidia-nscq.so.2"
              "usr/lib/x86_64-linux-gnu/libnvidia-nscq.so.2.0"
              "usr/lib/x86_64-linux-gnu/libnvidia-nscq.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-nvvm.so.4"
              "usr/lib/x86_64-linux-gnu/libnvidia-nvvm.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-nvvm70.so.4"
              "usr/lib/x86_64-linux-gnu/libnvidia-pkcs11-openssl3.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-ptxjitcompiler.so.1"
              "usr/lib/x86_64-linux-gnu/libnvidia-ptxjitcompiler.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-sandboxutils.so.1"
              "usr/lib/x86_64-linux-gnu/libnvidia-sandboxutils.so.595.71.05"
              "usr/lib/x86_64-linux-gnu/libnvidia-tileiras.so.595.71.05"
              "usr/share/nvidia/files.d"
              "usr/share/nvidia/nvswitch"
            ];
          }
        ];
        files =
          payload.accounts ./rootfs/etc
          ++ [
        {
          source = ./rootfs/etc/nftables.conf;
          target = "etc/nftables.conf";
          mode = "0644";
        }

            {
              source = ./rootfs/etc/containerd/config.toml;
              target = "etc/containerd/config.toml";
              mode = "0644";
            }
            {
              source = ./rootfs/etc/docker/daemon.json;
              target = "etc/docker/daemon.json";
              mode = "0644";
            }
            {
              source = ./rootfs/etc/nvidia-container-runtime/config.toml;
              target = "etc/nvidia-container-runtime/config.toml";
              mode = "0644";
            }
            {
              source = "${nvattest}/usr/bin/nvattest";
              target = "usr/bin/nvattest";
              mode = "0755";
            }
            {
              source = "${nvattest}/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2";
              target = "usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2";
              mode = "0644";
            }
          ]
          ++
            map
              (command: {
                source = "${docker}/${command}";
                target = "usr/bin/${command}";
                mode = "0755";
              })
              [
                "containerd"
                "containerd-shim-runc-v2"
                "dockerd"
                "runc"
              ]
          ++ map (name: {
            source = "${nvidia.modules}/${name}";
            target = "usr/lib/tinfoil/kernel-modules/${name}";
            mode = "0644";
          }) nvidia.moduleNames;
        replacements = [
          {
            source = ./rootfs/usr/share/nvidia/nvswitch/fabricmanager.cfg;
            target = "usr/share/nvidia/nvswitch/fabricmanager.cfg";
            mode = "0644";
          }
        ];
        symlinks = [
          {
            source = "libnvat.so.1.2.2";
            target = "usr/lib/x86_64-linux-gnu/libnvat.so.1";
          }
        ];
      };
    };
}

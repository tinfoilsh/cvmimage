"""Fixed positive assembly of the measured guest root filesystem."""

load(":runtime_package_inputs.bzl", "RUNTIME_PACKAGE_INPUTS")

_VENDORS = [
    ("docker-static", ":docker_static_members"),
    ("libnvidia-cfg1", ":libnvidia_cfg1_members"),
    ("libnvidia-compute", ":libnvidia_compute_members"),
    ("libnvidia-container-tools", ":libnvidia_container_tools_members"),
    ("libnvidia-container1", ":libnvidia_container1_members"),
    ("libnvidia-gpucomp", ":libnvidia_gpucomp_members"),
    ("libnvidia-nscq", ":libnvidia_nscq_members"),
    ("nvidia-container-toolkit-base", ":nvidia_container_toolkit_base_members"),
    ("nvidia-fabricmanager", ":nvidia_fabricmanager_members"),
    ("nvidia-firmware", ":nvidia_firmware_members"),
    ("nvidia-persistenced", ":nvidia_persistenced_members"),
]

_CONFIGS = [
    "etc/containerd/config.toml",
    "etc/docker/daemon.json",
    "etc/group",
    "etc/gshadow",
    "etc/hostname",
    "etc/hosts",
    "etc/nftables.conf",
    "etc/nsswitch.conf",
    "etc/nvidia-container-runtime/config.toml",
    "etc/passwd",
    "etc/resolv.conf",
    "etc/shadow",
]

def _rootfs_impl(ctx):
    archive = ctx.actions.declare_file("rootfs.tar")
    manifest = ctx.actions.declare_file("rootfs.tsv")
    runtime_files = ctx.attr._runtime[DefaultInfo].files.to_list()
    runtime_archive = [file for file in runtime_files if file.basename == "runtime-artifact-members.tar"]
    runtime_manifest = [file for file in runtime_files if file.basename == "runtime-artifact-members.tsv"]
    if len(runtime_archive) != 1 or len(runtime_manifest) != 1:
        fail("runtime artifact target must provide its fixed archive and manifest")
    arguments = [
        "--package-lock", ctx.file._package_lock.path,
        "--vendor-lock", ctx.file._vendor_lock.path,
        "--runtime-lock", ctx.file._runtime_lock.path,
        "--runtime-archive", runtime_archive[0].path,
        "--runtime-manifest", runtime_manifest[0].path,
        "--config-lock", ctx.file._config_lock.path,
    ]
    for source_id, source in zip(sorted(RUNTIME_PACKAGE_INPUTS), ctx.files._packages):
        arguments.extend(["--package", source_id, source.path])
    for (source_id, _), source in zip(_VENDORS, ctx.files._vendors):
        arguments.extend(["--vendor", source_id, source.path])
    for relative, source in zip(_CONFIGS, ctx.files._configs):
        arguments.extend(["--config", relative, source.path])
    arguments.extend(["--output-tar", archive.path, "--output-manifest", manifest.path])
    ctx.actions.run(
        executable = ctx.executable._tool,
        arguments = arguments,
        inputs = depset(
            ctx.files._packages + ctx.files._vendors + ctx.files._configs + runtime_files + [
                ctx.file._package_lock,
                ctx.file._vendor_lock,
                ctx.file._runtime_lock,
                ctx.file._config_lock,
            ],
        ),
        outputs = [archive, manifest],
        mnemonic = "TinfoilRootfs",
        progress_message = "Assembling fixed measured rootfs",
    )
    return [DefaultInfo(files = depset([archive, manifest]))]

rootfs = rule(
    implementation = _rootfs_impl,
    attrs = {
        "_config_lock": attr.label(default = ":rootfs-policy.sha256", allow_single_file = True),
        "_configs": attr.label_list(default = [":rootfs/" + path for path in _CONFIGS], allow_files = True),
        "_package_lock": attr.label(default = ":runtime-package-members.lock.json", allow_single_file = True),
        "_packages": attr.label_list(default = [":" + source_id + "_members" for source_id in sorted(RUNTIME_PACKAGE_INPUTS)], allow_files = True),
        "_runtime": attr.label(default = ":runtime-artifact-members"),
        "_runtime_lock": attr.label(default = ":manifests/rootfs-artifacts.lock.tsv", allow_single_file = True),
        "_tool": attr.label(default = "//scripts:rootfs_assembly", cfg = "exec", executable = True),
        "_vendor_lock": attr.label(default = ":runtime-sources.lock.json", allow_single_file = True),
        "_vendors": attr.label_list(default = [label for _, label in _VENDORS], allow_files = True),
    },
)

_ARTIFACTS = [
    ("libnvat.so.1.2.2", "_libnvat"),
    ("nvattest", "_nvattest"),
    ("nvidia-modeset.ko", "_nvidia_modeset"),
    ("nvidia-uvm.ko", "_nvidia_uvm"),
    ("nvidia.ko", "_nvidia"),
    ("tinfoil-boot", "_tinfoil_boot"),
    ("tinfoil-container-status", "_tinfoil_container_status"),
    ("tinfoil-egress", "_tinfoil_egress"),
    ("tinfoil-init", "_tinfoil_init"),
    ("tinfoil-shim", "_tinfoil_shim"),
]


def _runtime_artifacts_impl(ctx):
    archive = ctx.actions.declare_file("runtime-artifact-members.tar")
    manifest = ctx.actions.declare_file("runtime-artifact-members.tsv")
    arguments = [
        "archive",
        "--lock", ctx.file._lock.path,
        "--marker", ctx.file._marker.path,
    ]
    for source in ctx.files._manifests:
        arguments.extend(["--manifest", source.path])
    artifact_files = []
    for name, attribute in _ARTIFACTS:
        source = getattr(ctx.file, attribute)
        artifact_files.append(source)
        arguments.extend(["--file-name", name, "--file", source.path])
    arguments.extend(["--output-tar", archive.path, "--output-manifest", manifest.path])
    ctx.actions.run(
        executable = ctx.executable._tool,
        arguments = arguments,
        inputs = depset([ctx.file._lock, ctx.file._marker] + ctx.files._manifests + artifact_files),
        outputs = [archive, manifest],
        mnemonic = "RuntimeArtifactMembers",
    )
    return [DefaultInfo(files = depset([archive, manifest]))]


runtime_artifacts = rule(
    implementation = _runtime_artifacts_impl,
    attrs = {
        "_libnvat": attr.label(default = "//build/runtime-artifacts:producers/nvattest/usr/lib/x86_64-linux-gnu/libnvat.so.1.2.2", allow_single_file = True),
        "_lock": attr.label(default = "//image:manifests/rootfs-artifacts.lock.tsv", allow_single_file = True),
        "_manifests": attr.label_list(default = [
            "//build/runtime-artifacts:producers/go/rootfs-artifacts.tsv",
            "//build/runtime-artifacts:producers/nvattest/rootfs-artifacts.tsv",
            "//build/runtime-artifacts:producers/nvidia-modules/rootfs-artifacts.tsv",
        ], allow_files = True),
        "_marker": attr.label(default = "//build/runtime-artifacts:.tinfoil-runtime-artifacts-v1", allow_single_file = True),
        "_nvattest": attr.label(default = "//build/runtime-artifacts:producers/nvattest/usr/bin/nvattest", allow_single_file = True),
        "_nvidia": attr.label(default = "//build/runtime-artifacts:producers/nvidia-modules/artifacts/nvidia.ko", allow_single_file = True),
        "_nvidia_modeset": attr.label(default = "//build/runtime-artifacts:producers/nvidia-modules/artifacts/nvidia-modeset.ko", allow_single_file = True),
        "_nvidia_uvm": attr.label(default = "//build/runtime-artifacts:producers/nvidia-modules/artifacts/nvidia-uvm.ko", allow_single_file = True),
        "_tinfoil_boot": attr.label(default = "//build/runtime-artifacts:producers/go/artifacts/tinfoil-boot", allow_single_file = True),
        "_tinfoil_container_status": attr.label(default = "//build/runtime-artifacts:producers/go/artifacts/tinfoil-container-status", allow_single_file = True),
        "_tinfoil_egress": attr.label(default = "//build/runtime-artifacts:producers/go/artifacts/tinfoil-egress", allow_single_file = True),
        "_tinfoil_init": attr.label(default = "//build/runtime-artifacts:producers/go/artifacts/tinfoil-init", allow_single_file = True),
        "_tinfoil_shim": attr.label(default = "//build/runtime-artifacts:producers/go/artifacts/tinfoil-shim", allow_single_file = True),
        "_tool": attr.label(default = "//scripts:runtime_artifact_bridge", cfg = "exec", executable = True),
    },
)

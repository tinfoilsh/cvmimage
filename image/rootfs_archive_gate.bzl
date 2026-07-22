"""Verification-only gate for the fixed measured rootfs archive."""


def _runfile(workspace, file):
    return "${RUNFILES_DIR}/%s/%s" % (workspace, file.short_path)


def _rootfs_archive_gate_impl(ctx):
    rootfs_files = ctx.attr._rootfs[DefaultInfo].files.to_list()
    archives = [file for file in rootfs_files if file.basename == "rootfs.tar"]
    manifests = [file for file in rootfs_files if file.basename == "rootfs.tsv"]
    if len(archives) != 1 or len(manifests) != 1:
        fail("rootfs target must provide exactly rootfs.tar and rootfs.tsv")

    executable = ctx.actions.declare_file(ctx.label.name + ".sh")
    workspace = ctx.workspace_name
    tool = ctx.attr._tool[DefaultInfo].files_to_run.executable
    namespace = ctx.attr._namespace[DefaultInfo].files_to_run.executable
    inputs = [
        ("rootfs.tar", archives[0]),
        ("generated.tsv", manifests[0]),
        ("expected.tsv", ctx.file._expected_manifest),
        ("archive.sha256", ctx.file._archive_lock),
    ]
    copies = [
        "cp -L -- \"%s\" \"${inputs}/%s\"" % (_runfile(workspace, file), name)
        for name, file in inputs
    ]
    ctx.actions.write(
        executable,
        "#!/bin/sh\nset -eu\numask 077\ninputs=\"${TEST_TMPDIR:?}/rootfs-archive-gate-inputs\"\nmkdir \"${inputs}\"\n%s\nexec \"%s\" \"%s\" --archive \"${inputs}/rootfs.tar\" --generated-manifest \"${inputs}/generated.tsv\" --expected-manifest \"${inputs}/expected.tsv\" --archive-lock \"${inputs}/archive.sha256\"\n" % (
            "\n".join(copies),
            _runfile(workspace, namespace),
            _runfile(workspace, tool),
        ),
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = rootfs_files + [ctx.file._expected_manifest, ctx.file._archive_lock])
    runfiles = runfiles.merge(ctx.attr._tool[DefaultInfo].default_runfiles)
    runfiles = runfiles.merge(ctx.attr._namespace[DefaultInfo].default_runfiles)
    return [DefaultInfo(executable = executable, runfiles = runfiles)]


rootfs_archive_gate_test = rule(
    implementation = _rootfs_archive_gate_impl,
    test = True,
    attrs = {
        "_archive_lock": attr.label(default = ":manifests/rootfs.archive.sha256", allow_single_file = True),
        "_expected_manifest": attr.label(default = ":manifests/rootfs.expected.tsv", allow_single_file = True),
        "_namespace": attr.label(default = "//scripts:rootfs_archive_namespace", cfg = "exec", executable = True),
        "_rootfs": attr.label(default = ":rootfs"),
        "_tool": attr.label(default = "//scripts:rootfs_archive_gate", cfg = "exec", executable = True),
    },
)

"""Exact positive extraction of members declared by a runtime source lock."""


def _runtime_archive_impl(ctx):
    output = ctx.actions.declare_file(ctx.attr.out)
    args = ctx.actions.args()
    args.add("--archive", ctx.file.archive)
    args.add("--source-lock", ctx.file.source_lock)
    args.add("--output", output)
    if ctx.attr.source_id:
        args.add("--source-id", ctx.attr.source_id)
    inputs = [ctx.file.archive, ctx.file.source_lock]
    if ctx.file.validation:
        inputs.append(ctx.file.validation)
    ctx.actions.run(
        arguments = [args],
        executable = ctx.executable._extractor,
        inputs = inputs,
        mnemonic = "ExactRuntimeArchive",
        outputs = [output],
        progress_message = "Extracting locked runtime members for %{label}",
    )
    return [DefaultInfo(files = depset([output]))]


runtime_archive = rule(
    implementation = _runtime_archive_impl,
    attrs = {
        "archive": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.string(mandatory = True),
        "source_id": attr.string(),
        "source_lock": attr.label(allow_single_file = [".json"], mandatory = True),
        "validation": attr.label(allow_single_file = True),
        "_extractor": attr.label(
            cfg = "exec",
            default = "//scripts:runtime_archive_tool",
            executable = True,
        ),
    },
)


def _runtime_archive_lock_check_impl(ctx):
    output = ctx.actions.declare_file(ctx.attr.out)
    args = ctx.actions.args()
    args.add("--source-lock", ctx.file.source_lock)
    args.add("--output", output)
    args.add_all(ctx.attr.source_ids, before_each = "--validate-source-id")
    ctx.actions.run(
        arguments = [args],
        executable = ctx.executable._extractor,
        inputs = [ctx.file.source_lock],
        mnemonic = "ValidateRuntimeArchiveLock",
        outputs = [output],
    )
    return [DefaultInfo(files = depset([output]))]


runtime_archive_lock_check = rule(
    implementation = _runtime_archive_lock_check_impl,
    attrs = {
        "out": attr.string(mandatory = True),
        "source_ids": attr.string_list(mandatory = True),
        "source_lock": attr.label(allow_single_file = [".json"], mandatory = True),
        "_extractor": attr.label(
            cfg = "exec",
            default = "//scripts:runtime_archive_tool",
            executable = True,
        ),
    },
)


def _runtime_package_inputs_manifest_impl(ctx):
    lines = []
    inputs = []
    for source_id, target in sorted(ctx.attr.sources.items()):
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("package input must produce exactly one file: " + source_id)
        lines.append(source_id + "\t" + files[0].path)
        inputs.append(files[0])
    output = ctx.actions.declare_file(ctx.attr.out)
    ctx.actions.write(output, "\n".join(lines) + "\n")
    return [DefaultInfo(files = depset([output] + inputs))]


runtime_package_inputs_manifest = rule(
    implementation = _runtime_package_inputs_manifest_impl,
    attrs = {
        "out": attr.string(mandatory = True),
        "sources": attr.string_keyed_label_dict(allow_files = True, mandatory = True),
    },
)

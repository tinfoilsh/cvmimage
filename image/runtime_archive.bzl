"""Exact positive extraction of members declared by a runtime source lock."""


def _runtime_archive_impl(ctx):
    output = ctx.actions.declare_file(ctx.attr.out)
    args = ctx.actions.args()
    args.add("--archive", ctx.file.archive)
    args.add("--source-lock", ctx.file.source_lock)
    args.add("--output", output)
    ctx.actions.run(
        arguments = [args],
        executable = ctx.executable._extractor,
        inputs = [ctx.file.archive, ctx.file.source_lock],
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
        "source_lock": attr.label(allow_single_file = [".json"], mandatory = True),
        "_extractor": attr.label(
            cfg = "exec",
            default = "//scripts:runtime_archive_tool",
            executable = True,
        ),
    },
)

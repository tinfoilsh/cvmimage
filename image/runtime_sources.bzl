"""Repositories derived directly from the canonical runtime source lock."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

_DEB_PAYLOAD_BUILD = """load("@rules_distroless//apt/private:deb_postfix.bzl", "deb_postfix")

deb_postfix(
    name = "payload",
    srcs = glob(["data.tar*"]),
    outs = ["layer.tar.gz"],
    mergedusr = False,
    visibility = ["//visibility:public"],
)
"""

_TAR_PAYLOAD_BUILD = """package(default_visibility = ["//visibility:public"])

filegroup(
    name = "payload",
    srcs = glob(["**"], exclude = ["BUILD.bazel", "REPO.bazel"]),
)
"""


def _repository_name(source_id):
    return "runtime_source_" + source_id.replace("-", "_")


def _valid_source_id(source_id):
    if not source_id or source_id[0] == "-" or source_id[-1] == "-":
        return False
    for character in source_id.elems():
        if character not in "abcdefghijklmnopqrstuvwxyz0123456789-":
            return False
    return True


def _runtime_sources_impl(module_ctx):
    lock_tags = []
    for module in module_ctx.modules:
        for tag in module.tags.from_lock:
            if not module.is_root:
                fail("runtime source locks may only be declared by the root module")
            lock_tags.append(tag)
    if len(lock_tags) != 1:
        fail("exactly one runtime_sources.from_lock tag is required")

    lock = json.decode(module_ctx.read(lock_tags[0].lock))
    if lock.get("version") != 1:
        fail("unsupported runtime source lock format")
    sources = lock.get("sources")
    if type(sources) != "list" or not sources:
        fail("runtime source lock must contain a non-empty sources list")

    seen = {}
    seen_repositories = {}
    for source in sources:
        source_id = source.get("id")
        if type(source_id) != "string" or not _valid_source_id(source_id):
            fail("runtime source id must use lowercase letters, digits, and interior hyphens")
        if source_id in seen:
            fail("duplicate runtime source id: %s" % source_id)
        seen[source_id] = True
        repository_name = _repository_name(source_id)
        if repository_name in seen_repositories:
            fail("runtime source repository-name collision: %s and %s" % (seen_repositories[repository_name], source_id))
        seen_repositories[repository_name] = source_id
        kind = source.get("kind")
        if kind not in ["deb", "tar"]:
            fail("runtime source %s has an unsupported kind" % source_id)
        url = source.get("url")
        sha256 = source.get("sha256")
        if type(url) != "string" or not url.startswith("https://"):
            fail("runtime source %s must use an HTTPS URL" % source_id)
        if type(sha256) != "string" or len(sha256) != 64:
            fail("runtime source %s has an invalid SHA256" % source_id)
        if kind == "deb":
            if source.get("strip_prefix") != None:
                fail("runtime DEB source %s may not set strip_prefix" % source_id)
            http_archive(
                name = repository_name,
                build_file_content = _DEB_PAYLOAD_BUILD,
                sha256 = sha256,
                type = ".deb",
                urls = [url],
            )
        else:
            strip_prefix = source.get("strip_prefix", "")
            if type(strip_prefix) != "string":
                fail("runtime tar source %s has a non-string strip_prefix" % source_id)
            http_archive(
                name = repository_name,
                build_file_content = _TAR_PAYLOAD_BUILD,
                sha256 = sha256,
                strip_prefix = strip_prefix,
                urls = [url],
            )


_from_lock = tag_class(
    attrs = {"lock": attr.label(mandatory = True)},
)


runtime_sources = module_extension(
    implementation = _runtime_sources_impl,
    tag_classes = {"from_lock": _from_lock},
)

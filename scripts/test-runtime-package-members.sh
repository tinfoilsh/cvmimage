#!/bin/sh
set -eu

lock=$1

PYTHONOPTIMIZE=1 python3 - "$lock" <<'PY'
import json
import sys
from copy import deepcopy

expected = [
    ('ca-certificates_20260223_amd64', 'etc/ssl/certs/ca-certificates.crt'),
    ('iproute2_6.19.0-1ubuntu1_amd64', 'usr/bin/ip'),
    ('iproute2_6.19.0-1ubuntu1_amd64', 'usr/sbin/ip'),
    ('libbpf1_1-1.6.3-1ubuntu1_amd64', 'usr/lib/x86_64-linux-gnu/libbpf.so.1'),
    ('libbpf1_1-1.6.3-1ubuntu1_amd64', 'usr/lib/x86_64-linux-gnu/libbpf.so.1.6.3'),
    ('libbsd0_0.12.2-2build2_amd64', 'usr/lib/x86_64-linux-gnu/libbsd.so.0'),
    ('libbsd0_0.12.2-2build2_amd64', 'usr/lib/x86_64-linux-gnu/libbsd.so.0.12.2'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libc.so.6'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libdl.so.2'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libm.so.6'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libpthread.so.0'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libresolv.so.2'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/librt.so.1'),
    ('libc6_2.43-2ubuntu2_amd64', 'usr/lib64/ld-linux-x86-64.so.2'),
    ('libcap2_1-2.75-10ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libcap.so.2'),
    ('libcap2_1-2.75-10ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libcap.so.2.75'),
    ('libcom-err2_1.47.2-3ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libcom_err.so.2'),
    ('libcom-err2_1.47.2-3ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libcom_err.so.2.1'),
    ('libedit2_3.1-20251016-1_amd64', 'usr/lib/x86_64-linux-gnu/libedit.so.2'),
    ('libedit2_3.1-20251016-1_amd64', 'usr/lib/x86_64-linux-gnu/libedit.so.2.0.76'),
    ('libelf1t64_0.194-4_amd64', 'usr/lib/x86_64-linux-gnu/libelf-0.194.so'),
    ('libelf1t64_0.194-4_amd64', 'usr/lib/x86_64-linux-gnu/libelf.so.1'),
    ('libgcc-s1_16-20260322-1ubuntu1_amd64', 'usr/lib/x86_64-linux-gnu/libgcc_s.so.1'),
    ('libgmp10_2-6.3.0-p-dfsg-5ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libgmp.so.10'),
    ('libgmp10_2-6.3.0-p-dfsg-5ubuntu2_amd64', 'usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0'),
    ('libgssapi-krb5-2_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2'),
    ('libgssapi-krb5-2_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2.2'),
    ('libjansson4_2.14-2build4_amd64', 'usr/lib/x86_64-linux-gnu/libjansson.so.4'),
    ('libjansson4_2.14-2build4_amd64', 'usr/lib/x86_64-linux-gnu/libjansson.so.4.14.0'),
    ('libk5crypto3_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libk5crypto.so.3'),
    ('libk5crypto3_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libk5crypto.so.3.1'),
    ('libkeyutils1_1.6.3-6ubuntu3_amd64', 'usr/lib/x86_64-linux-gnu/libkeyutils.so.1'),
    ('libkeyutils1_1.6.3-6ubuntu3_amd64', 'usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10'),
    ('libkrb5-3_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libkrb5.so.3'),
    ('libkrb5-3_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libkrb5.so.3.3'),
    ('libkrb5support0_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libkrb5support.so.0'),
    ('libkrb5support0_1.22.1-2ubuntu4_amd64', 'usr/lib/x86_64-linux-gnu/libkrb5support.so.0.1'),
    ('libmd0_1.1.0-2build4_amd64', 'usr/lib/x86_64-linux-gnu/libmd.so.0'),
    ('libmd0_1.1.0-2build4_amd64', 'usr/lib/x86_64-linux-gnu/libmd.so.0.1.0'),
    ('libmnl0_1.0.5-3build1_amd64', 'usr/lib/x86_64-linux-gnu/libmnl.so.0'),
    ('libmnl0_1.0.5-3build1_amd64', 'usr/lib/x86_64-linux-gnu/libmnl.so.0.2.0'),
    ('libnftables1_1.1.6-1_amd64', 'usr/lib/x86_64-linux-gnu/libnftables.so.1'),
    ('libnftables1_1.1.6-1_amd64', 'usr/lib/x86_64-linux-gnu/libnftables.so.1.1.0'),
    ('libnftnl11_1.3.1-1_amd64', 'usr/lib/x86_64-linux-gnu/libnftnl.so.11'),
    ('libnftnl11_1.3.1-1_amd64', 'usr/lib/x86_64-linux-gnu/libnftnl.so.11.7.0'),
    ('libpcre2-8-0_10.46-1build1_amd64', 'usr/lib/x86_64-linux-gnu/libpcre2-8.so.0'),
    ('libpcre2-8-0_10.46-1build1_amd64', 'usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.14.0'),
    ('libseccomp2_2.6.0-2ubuntu5_amd64', 'usr/lib/x86_64-linux-gnu/libseccomp.so.2'),
    ('libseccomp2_2.6.0-2ubuntu5_amd64', 'usr/lib/x86_64-linux-gnu/libseccomp.so.2.6.0'),
    ('libselinux1_3.9-4build1_amd64', 'usr/lib/x86_64-linux-gnu/libselinux.so.1'),
    ('libssl3t64_3.5.5-1ubuntu3.2_amd64', 'usr/lib/x86_64-linux-gnu/libcrypto.so.3'),
    ('libstdc-p--p-6_16-20260322-1ubuntu1_amd64', 'usr/lib/x86_64-linux-gnu/libstdc++.so.6'),
    ('libstdc-p--p-6_16-20260322-1ubuntu1_amd64', 'usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.35'),
    ('libtinfo6_6.6-p-20251231-1_amd64', 'usr/lib/x86_64-linux-gnu/libtinfo.so.6'),
    ('libtinfo6_6.6-p-20251231-1_amd64', 'usr/lib/x86_64-linux-gnu/libtinfo.so.6.6'),
    ('libtirpc-common_1.3.7-0.1_amd64', 'etc/netconfig'),
    ('libtirpc3t64_1.3.7-0.1_amd64', 'usr/lib/x86_64-linux-gnu/libtirpc.so.3'),
    ('libtirpc3t64_1.3.7-0.1_amd64', 'usr/lib/x86_64-linux-gnu/libtirpc.so.3.0.0'),
    ('libxml2-16_2.15.2-p-dfsg-0.1_amd64', 'usr/lib/x86_64-linux-gnu/libxml2.so.16'),
    ('libxml2-16_2.15.2-p-dfsg-0.1_amd64', 'usr/lib/x86_64-linux-gnu/libxml2.so.16.1.2'),
    ('libxtables12_1.8.11-2ubuntu3_amd64', 'usr/lib/x86_64-linux-gnu/libxtables.so.12'),
    ('libxtables12_1.8.11-2ubuntu3_amd64', 'usr/lib/x86_64-linux-gnu/libxtables.so.12.7.0'),
    ('libzstd1_1.5.7-p-dfsg-3_amd64', 'usr/lib/x86_64-linux-gnu/libzstd.so.1'),
    ('libzstd1_1.5.7-p-dfsg-3_amd64', 'usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7'),
    ('nftables_1.1.6-1_amd64', 'usr/sbin/nft'),
    ('openssl_3.5.5-1ubuntu3.2_amd64', 'etc/ssl/openssl.cnf'),
    ('openssl_3.5.5-1ubuntu3.2_amd64', 'usr/lib/ssl/openssl.cnf'),
    ('zlib1g_1-1.3.dfsg-p-really1.3.1-1ubuntu3_amd64', 'usr/lib/x86_64-linux-gnu/libz.so.1'),
    ('zlib1g_1-1.3.dfsg-p-really1.3.1-1ubuntu3_amd64', 'usr/lib/x86_64-linux-gnu/libz.so.1.3.1'),
]


class ValidationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate(document):
    require(isinstance(document, dict), "package-member lock must be an object")
    require(set(document) == {"sources", "version"}, "unexpected package-member lock fields")
    require(type(document["version"]) is int and document["version"] == 1, "unexpected package-member lock version")
    require(isinstance(document["sources"], dict), "package-member sources must be an object")
    require(len(document["sources"]) == 35, "package-member lock must contain exactly 35 sources")
    actual = []
    for source_id, source in document["sources"].items():
        require(isinstance(source, dict), f"invalid source record: {source_id}")
        require(set(source) == {"files", "kind", "package_data"}, f"invalid source record: {source_id}")
        require(source["kind"] == "tar", f"invalid source kind: {source_id}")
        require(type(source["package_data"]) is bool and source["package_data"] is True, f"invalid package-data mode: {source_id}")
        require(isinstance(source["files"], list), f"invalid source files: {source_id}")
        for entry in source["files"]:
            actual.append((source_id, entry["path"]))
            require(
                type(entry["uid"]) is int
                and entry["uid"] == 0
                and type(entry["gid"]) is int
                and entry["gid"] == 0
                and isinstance(entry["xattrs"], dict)
                and entry["xattrs"] == {},
                f"invalid ownership or xattrs: {source_id}: {entry['path']}",
            )
    require(len(actual) == 70, "package-member lock must contain exactly 70 paths")
    require(len(actual) == len(set(actual)), "package-member lock contains duplicate paths")
    if actual != expected:
        raise ValidationError({
            "missing": [item for item in expected if item not in actual],
            "extra": [item for item in actual if item not in expected],
        })


require(sys.flags.optimize == 1, "adversarial test must run with Python assertions disabled")
document = json.load(open(sys.argv[1], encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
validate(document)
mutated = deepcopy(document)
extra = dict(mutated["sources"]["iproute2_6.19.0-1ubuntu1_amd64"]["files"][0])
extra["path"] = "usr/bin/extra"
mutated["sources"]["iproute2_6.19.0-1ubuntu1_amd64"]["files"].append(extra)
try:
    validate(mutated)
except ValidationError:
    pass
else:
    raise ValidationError("exact inventory accepted an extra selected path")
PY

# Fixed debug image

`make debug-image` builds `tinfoilcvm-debug.*` with the exact pinned release
kernel and additive initrd. The root filesystem intentionally differs: it
adds one debug-only layer containing the pinned Ubuntu `busybox-static` payload
and a `tinfoil_debug_image` build-tag replacement for `/usr/bin/tinfoil-init`.

That PID1 launches one fixed interactive BusyBox `ash` child on `/dev/hvc0`
before normal boot continues. There is no kernel command-line switch, path
parser, fallback shell, or runtime activation mechanism. The release PID1 is
built without the tag, and `shipping-image` never consumes the debug rootfs.

The normal Bazel rootfs is not rebuilt or duplicated in that layer. The debug
measurement is diagnostic and must never be promoted. The separate tagged Go
target and fixed Bazel layer make the compile-time boundary explicit; actual
debug-image boots qualify the console behavior. IBT and NVIDIA qualification
remain separate evidence-driven work.

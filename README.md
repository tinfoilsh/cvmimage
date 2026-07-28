# Tinfoil Confidential VM

Tinfoil CVM is a confidential virtual machine for secure inference and custom compute workloads on AMD SEV-SNP and Intel TDX.

## Building

Every artifact builds from the top-level `default.nix` with pinned inputs.
Build a target with:

```sh
nix-build -I . -A <target>
```

| Target | Output |
| --- | --- |
| `shipping-image` | Measured release set: `tinfoilcvm.raw`, `tinfoilcvm.vmlinuz`, `tinfoilcvm.initrd`, `tinfoilcvm.roothash` |
| `debug-image` | Shipping layout plus the debug rootfs layer |
| `rootfs-archive` | Additive runtime rootfs archive |
| `debug-rootfs-layer` | Debug overlay used only by `debug-image` |
| `kernel-artifacts` | Custom kernel, modules, and `Module.symvers` |
| `nvidia-modules` | Validated NVIDIA open kernel modules |
| `initrd` | Compressed fixed-CPIO initrd |
| `runtime-go` | The five CGO runtime commands |
| `debug-init` | Compile-time debug PID1 |
| `tinfoil-initrd` | Pure-Go initrd command |
| `fixed-cpio-writer` | Deterministic CPIO writer used by `initrd` |
| `nvattest` | NVIDIA attestation CLI and `libnvat` |
| `checks` | Go source tests |
| `runtime-package-lock` | Regenerated Ubuntu package lock (only when changing package inputs) |

See `docs/build.md` for the complete source-to-measurement build graph, tool
ownership boundaries, builder configuration, and release qualification model.

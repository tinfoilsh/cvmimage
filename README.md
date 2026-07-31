# Tinfoil Confidential VM

Tinfoil CVM is a confidential virtual machine for secure inference and custom compute workloads on AMD SEV-SNP and Intel TDX.

Every byte of the final image is explicitly declared and derived from pinned inputs, the hermetic build is byte-for-byte reproducible, and anyone can audit the complete source-to-measurement graph themselves.

## Building

On an x86_64 Linux host without Nix, first install the pinned Nix release:

```sh
./nix/install.sh
```

Then build the CVM image:

```sh
nix-build -I . -A shipping-image -o result
```

This will produce the measured release artifacts: `tinfoilcvm.raw`, `tinfoilcvm.vmlinuz`, `tinfoilcvm.initrd`, `tinfoilcvm.roothash`.

See `docs/build.md` for more details.
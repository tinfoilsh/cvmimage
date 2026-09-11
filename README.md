# Tinfoil Confidential VM

Tinfoil CVM is a confidential virtual machine for secure inference and custom compute workloads on AMD SEV-SNP and Intel TDX.

Every byte of the final image is explicitly declared and derived from pinned inputs, the hermetic build is byte-for-byte reproducible, and anyone can audit the complete source-to-measurement graph themselves.

## Building

On an x86_64 Linux host without Nix, first install the pinned Nix release:

```sh
./nix/install.sh
export PATH="/nix/var/nix/profiles/default/bin:$PATH"
```

Then build the CVM images:

```sh
nix-build -I . -A inference-image -o result
nix-build -I . -A sandbox-image -o result-sandbox
```

The inference image carries the NVIDIA stack and runs containers; the sandbox image carries no NVIDIA payload and no container runtime, and instead runs `tinfoil-sandbox`, which unlocks an encrypted workspace volume and opens SSH to its enrolled owner. Each produces the measured release artifacts `<name>.raw`, `<name>.vmlinuz`, `<name>.initrd`, `<name>.roothash`, with `tinfoilcvm` and `tinfoilcvm-sandbox` as the names.

Each variant declares its binaries, packages, files, and kernel fragments in
`inference/default.nix` or `sandbox/default.nix`. Their sibling Go modules
supply boot, lifecycle, and shim specs to the shared `tinfoil/` platform.

See [docs/build.md](docs/build.md) for the build outputs and ownership map.

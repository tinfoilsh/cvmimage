# Image build

The image build has two implementation boundaries and one small user
interface:

1. Nix builds every content input to the image.
2. mkosi turns those exact inputs into the partitioned disk and dm-verity
   metadata.
3. Make exposes the supported commands without owning another build graph.

The builder is trusted. Nix is used to make inputs, dependencies, and assembly
explicit and reproducible, not to attest intermediate artifacts or to verify a
second hidden construction of the same filesystem.

## Graph

```mermaid
flowchart TD
    S["Pinned repository sources"] --> N["Pinned Nix build graph"]
    U["Locked Ubuntu and NVIDIA archives"] --> N
    T["Pinned Go, C, Rust, kernel, and packaging tools"] --> N
    C["Repository rootfs configuration"] --> N

    N --> G["Runtime Go binaries"]
    N --> A["nvattest and libnvat"]
    N --> K["Custom kernel"]
    K --> V["Three NVIDIA modules"]
    N --> I["Fixed initrd.cpio.zst"]

    G --> R["Additive rootfs.tar"]
    A --> R
    V --> R
    C --> R

    R --> M["Pinned offline mkosi finalizer"]
    I --> X["Release artifact set"]
    K --> X
    M --> X

    X --> Q["Release-only repeated builds and hardware qualification"]
```

There is no Docker builder, Bazel packaging layer, generated manifest
language, artifact cache protocol, or digest handoff between these steps.

## Nix ownership

The top-level `default.nix` pins one Nixpkgs source and exposes the complete set
of image inputs:

| Output | Owner | Declaration |
| --- | --- | --- |
| Runtime and debug Go binaries | Nixpkgs `buildGoModule` | `nix/go.nix`, `tinfoil/go.mod`, `tinfoil/go.sum` |
| Fixed initrd | Nix-built Go CPIO writer and Zstandard | `nix/initrd.nix`, `image/initrd/writer.go` |
| Custom kernel | Nixpkgs `linuxManualConfig` | `nix/kernel.nix`, `kernel/tinfoil-cvm-7.0.defconfig`, `kernel/config.d/10-tinfoil-cvm-policy.config` |
| Three NVIDIA modules | Nixpkgs kernel-module build | `nix/nvidia-modules.nix` |
| nvattest and libnvat | Nixpkgs CMake and Rust builders | `nix/nvattest.nix`, `nix/locks/regorus.Cargo.lock` |
| Ubuntu and vendor payloads | Fixed-output archive fetches | `image/runtime-packages.lock.json`, `nix/runtime-sources.nix` |
| Repository configuration | Direct additive copy | `image/rootfs/` |
| Rootfs and debug layer archives | Fixed tar materializer | `nix/rootfs.nix` |

`nix/rootfs.nix` is additive: it starts from an empty tree and installs only
the declared archive members, Nix-built outputs, and repository files. Package
maintainer scripts do not run and no producer filesystem is copied into the
image. Complete package payloads are accepted where they are the clearest
contract; later TCB reduction should remove them only with evidence that the
smaller contract is correct.

The Nix expressions also reject store references in runtime binaries and use
fixed ownership, modes, archive ordering, and timestamps. Reproducibility is a
property demonstrated by repeated clean builds and cross-host comparison; it
is not inferred merely from using Nix.

## mkosi ownership

mkosi is fetched from the pinned Nixpkgs revision. It receives only:

- `rootfs.tar`;
- the debug rootfs layer for `debug-image`; and
- the fixed partition definitions in `mkosi.repart/`.

It performs no package installation or network access. Its narrow job is to
create the root filesystem image, partition layout, and dm-verity metadata.
The kernel and initrd are copied directly from their Nix outputs into the
release artifact set.

## Make interface

The Makefile is intentionally not a second dependency graph:

```sh
make rootfs
make shipping-image
make debug-image
make test
make clean
```

Each build command asks Nix for named outputs. The two image commands then call
the pinned mkosi binary with those exact paths. `make test` owns repository Go
tests, focused race and debug-tag tests, vet, and a fixed-initrd build.

Direct Nix outputs remain available for focused work, for example:

```sh
nix-build --option sandbox true -A runtime-go
nix-build --option sandbox true -A kernel-artifacts
nix-build --option sandbox true -A nvidia-modules
nix-build --option sandbox true -A nvattest
nix-build --option sandbox true -A rootfs-archive
nix-build --option sandbox true -A initrd
```

## Release qualification

Normal pull-request CI checks evaluation, focused builds, and source tests. It
does not rebuild expensive producers twice. Before promoting a release, build
the exact candidate independently on the qualified builders, compare the
kernel, initrd, rootfs, raw disk, and dm-verity root, then boot and exercise the
same artifacts on the required CPU and GPU hardware. Promote only the tested
measurement. This is a release process, not another verifier embedded in the
build graph.

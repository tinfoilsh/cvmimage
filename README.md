# Tinfoil Confidential VM

Tinfoil CVM is a confidential virtual machine for secure inference and custom compute workloads on AMD SEV-SNP and Intel TDX.

Every byte of the final image is explicitly declared and derived from pinned inputs, the hermetic build is byte-for-byte reproducible, and anyone can audit the complete source-to-measurement graph themselves.

## Configuring a workload

Pin the CVM release in `tinfoil-config.yml`:

```yaml
cvm-version: "<version>@sha256:<manifest-sha256>"
```

The digest is the SHA-256 of the release's `tinfoil-inference-v<version>-manifest.json`.
[Release notes](https://github.com/tinfoilsh/cvmimage/releases) include the complete
config line; stable releases also update this example automatically.

The default pin selects the CPU image. Add `+gpu` before `@sha256:` to select
the GPU image from the same manifest. The selector is part of the approved
config; `gpus` specifies the hardware count independently.

## Building

On an x86_64 Linux host without Nix, first install the pinned Nix release:

```sh
./nix/install.sh
export PATH="/nix/var/nix/profiles/default/bin:$PATH"
```

Then build the CVM image:

```sh
nix-build -I . -A shipping-image -o result
```

Use `-A variants.gpu.shipping-image` for the GPU image. The CPU image excludes
NVIDIA drivers, firmware, CUDA libraries, GPU services and attestation, and
kernel module support. Both variants share the same Nix inputs and build logic.

This will produce the measured release artifacts: `tinfoilcvm.raw`, `tinfoilcvm.vmlinuz`, `tinfoilcvm.initrd`, `tinfoilcvm.roothash`.

The repository also holds `firmware/`, the measured state a confidential guest
launches with, and `compiler/`, the `cvmc` command that turns it into an IGVM
image and reports what that image measures.

See `docs/build.md` and `docs/launch.md` for more details.

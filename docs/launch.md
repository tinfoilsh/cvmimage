# The measured launch: `firmware/` and `compiler/`

- **`firmware/`** is what the guest executes and the state it starts from: the
  reset stubs, the guest-physical map, the ACPI tables, the zero page and its
  E820 map, the page tables, and on SEV-SNP one Virtual Machine Save Area
  (VMSA) per processor. All of it is measured.
- **`compiler/`** is the `cvmc` command, which serializes that state into an
  Independent Guest Virtual Machine (IGVM) image and reports the launch digest
  it produces.

```sh
cvmc build --platform tdx|snp --kernel … --initramfs … --output image.igvm
cvmc measure image.igvm
```

`measure` runs the same digest code `build` ran, so the two cannot drift. It
exists so a published measurement can be checked against the image shipped
beside it without reproducing the build.

The split is the trust boundary: a client trusts `firmware/` because its bytes
are measured and should be able to read all of it, while `compiler/` is trusted
only by whoever cuts a release.

## Why

A confidential VM does not start in the state the [Linux x86 boot
protocol](https://github.com/torvalds/linux/blob/master/Documentation/arch/x86/boot.rst)
requires. Firmware normally bridges that gap, taking much of its configuration
from the host — flexibility that is unnecessary when the workload is fixed
before launch, and that makes anything loaded after the initial measurement
harder to account for.

`cvmc` prepares the whole boot environment at build time, so boot reduces to a
4 KiB reset shim that establishes processor state, initializes private RAM, and
enters Linux.

## Design

At build time the compiler validates the `bzImage`, places the kernel and
initramfs, and constructs the zero page, E820 map, ACPI tables, GDT, stack,
command line and identity page tables.

Pages already imported must not be accepted or validated again, so the build
produces one placement map covering the E820 map handed to Linux, the pages
imported from the IGVM file, and the ranges the reset shim initializes.

On TDX every image page contributes to the measurement register for the trust
domain (MRTD). The shim enters long mode, parks
application processors in the ACPI wakeup mailbox, accepts the remaining
private RAM, and jumps to Linux.

On SEV-SNP the digest covers the normal pages and one VMSA per processor. The
shim enters long mode, validates and clears the remaining private RAM, wakes
the application processors, and jumps to Linux.

Each SEV-SNP application processor launches from its own measured VMSA into a
park stub and waits on a Guest-Hypervisor Communication Block (GHCB) AP Reset
Hold until Linux replaces its VMSA through the GHCB AP-creation call. KVM starts
every non-boot processor in wait-for-SIPI and only an INIT takes it out, so the
boot processor sends INIT-SIPI-SIPI first, as firmware would. Under SEV-ES the
local APIC is reachable only through the GHCB, so the shim rescinds one measured
page, makes it shared, registers it as its GHCB, issues the three
interrupt-command writes through it, and returns the page to private.

The SNP image reaches Linux through a confidential-computing blob on the
`setup_data` chain. The record and the blob share one measured page of E820 RAM
and the record claims the whole page: Linux re-reads the chain long after boot
in `pcibios_device_add()`, and `memremap()` returns ciphertext for a page
outside the RAM map, leaving every PCI device without an MSI domain.

There is no later measured boot. No RTMR is extended, no event log is produced,
and no DICE identity is derived.

## Build

Needs Rust, GNU `as` and GNU `objcopy`.

```sh
cargo run --release -p cvm-compiler -- build --platform tdx \
  --kernel /path/to/bzImage --initramfs /path/to/initramfs --output image.igvm

cargo run --release -p cvm-compiler -- build --platform snp \
  --kernel /path/to/bzImage --initramfs /path/to/initramfs \
  --id-key /path/to/id-key.pem --output image.igvm
```

Each writes an IGVM file and an adjacent JSON manifest holding the expected
launch measurement, component hashes, memory configuration, and the report
fields this image fixes.

| Option | Default | Meaning |
| --- | --- | --- |
| `--ram` | `1G` | Guest RAM, matching QEMU `-m` |
| `--vcpus` | `4` | Processor count; SNP measures one VMSA per processor |
| `--cmdline` | `panic=-1` | Linux command line |
| `--config-hash` | zero | TDX `MRCONFIGID` or SNP `HOST_DATA` |
| `--cbit` | `51` | SNP encryption bit |
| `--guest-svn` | `0` | SNP anti-rollback version |
| `--id-key` | none | Key signing the SNP ID block |

`no5lvl` is appended because the image uses four-level page tables.

## Run on TDX

```sh
qemu-system-x86_64 -accel kvm -m 1G -smp 4 -cpu host \
  -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,igvm-cfg=igvm0 \
  -object tdx-guest,id=tdx \
  -object igvm-cfg,id=igvm0,file=image.igvm \
  -nographic -nodefaults -serial stdio -no-reboot
```

Do not pass `-bios`, `-kernel`, `-initrd` or `-append`. Add `console=ttyS0` to
`--cmdline` for a serial console.

QEMU must be built with `--enable-igvm` against libigvm 0.3 or newer. Upstream
supports IGVM for SEV, SEV-ES and SEV-SNP but not TDX.

## SEV-SNP policy

The image uses guest policy `0x30133`: firmware ABI 1.51 or newer, debugging and
migration agents disabled. Pass it explicitly:

```sh
-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=5,policy=0x30133
```

The policy cannot express an SMT or single-socket requirement — KVM rejects
`SNP_LAUNCH_START` for a policy that clears the SMT bit or sets `SINGLE_SOCKET`,
so `PLATFORM_INFO` carries both instead.

With `--id-key` the compiler signs an ID block containing the expected
measurement, policy and guest SVN, and firmware rejects a launch that does not
match it.

## Memory map

For q35 guests with at least 2816 MiB, 2 GiB goes below 4 GiB, the rest above,
and the PCI aperture between them is derived from `--ram` alone. Pass QEMU the
same `-m`.

Private-memory initialization is linear in `--ram`; large SNP guests spend
several seconds validating and clearing it.

## Linux requirements

x86-64, boot protocol 2.12 or newer.

```text
CONFIG_INTEL_TDX_GUEST    CONFIG_SMP    CONFIG_ACPI    CONFIG_BLK_DEV_INITRD
CONFIG_AMD_MEM_ENCRYPT    CONFIG_SEV_GUEST                      (SEV-SNP also)
```

Hotplug, suspend, kexec and processor offlining are unsupported.

## Attestation

The launch measurement does not cover every setting a report carries, so a
verifier checks more than the digest. The remaining fields split in two, and the
split decides who may state them.

The manifest's `launch` object holds what **this image** fixes. A different
build changes them, so they belong with the measurement — and are authenticated
by whatever authenticates the manifest, which is itself unsigned.

TDX:

| Field | Value | Why the digest cannot carry it |
| --- | --- | --- |
| `mrtd` | the measurement | — |
| `mrconfigid` | `--config-hash` | Passed by the host at launch, chosen by this build |
| `rtmr0`-`rtmr3` | zero at launch | The image extends none, so anything the guest extends later stays visible |

SEV-SNP:

| Field | Value | Why the digest cannot carry it |
| --- | --- | --- |
| `measurement` | the launch digest | — |
| `policy` | `0x30133` | The file asks for it; only a signed ID block makes firmware refuse a launch that used another |
| `host_data` | `--config-hash` | Passed by the host at launch, chosen by this build |
| `guest_svn` | `--guest-svn`, zero unless `--id-key` signs one | An unsigned launch reports zero |
| `id_key_digest` | the `--id-key` digest, else zero | Zero says firmware enforced no digest at launch |

Every other report field describes the **machine**: TDX `ATTRIBUTES`, `XFAM`,
`MROWNER`, `MROWNERCONFIG`, `SERVTD_HASH`, `TEE_TCB_SVN`; SEV-SNP
`PLATFORM_INFO`, `SIGNER_INFO`, `REPORTED_TCB`, `VMPL`. This build cannot
observe any of them, so it does not state them. They belong to the verifier's
platform policy, alongside trusted computing base floors and endorsed machine
identities.

Two consequences the digest hides:

- A TD launched with `DEBUG` or `MIGRATABLE` set produces a byte-identical
  MRTD. Only a policy pinning `ATTRIBUTES` catches it.
- The guest policy allows simultaneous multithreading, because KVM refuses to
  launch a guest whose policy forbids it. Whether the host runs it is visible
  only in `PLATFORM_INFO`.

## Releases

A cvmimage version tag publishes `cvmc` alongside the kernel, initramfs and
root disk it was built against, recording its SHA-256 as `cvm_compiler` in the
release manifest, so tool and guest carry one version.

```sh
curl -O https://images.tinfoil.sh/cvm/cvmc-v1.2.3
gh attestation verify cvmc-v1.2.3 --repo tinfoilsh/cvmimage
```

That proves the binary came out of the release workflow rather than somebody's
laptop, but still trusts the machine that built it. Rebuilding removes that
trust, and is worth something only from a different machine:

```sh
git clone --branch v1.2.3 https://github.com/tinfoilsh/cvmimage && cd cvmimage
nix-build -I . -A cvm-compiler -o result-cvmc
sha256sum result-cvmc/bin/cvmc
```

## Reproducible build

`cargo build` pins rustc and nothing else, and rustc hands the final link to
`cc`: two machines with the same pinned rustc produced different binaries from
identical source, differing only in gcc, binutils and glibc versions.
`nix/compiler.nix` pins all of them at one nixpkgs revision and builds
statically.

```sh
nix-build -I . -A cvm-compiler -o result-cvmc   # -> result-cvmc/bin/cvmc
nix-build -I . -A cvm-compiler --check          # rebuild, fail if it moved
```

The pin covers GNU `as` and `objcopy` deliberately: `firmware/build.rs`
assembles the reset shims with them and those bytes land in the measured shim
page.

The two properties are separate. The *image* is already reproducible without
any of this — machines with different native toolchains emit the same IGVM
bytes and the same MRTD, because the image is data the firmware crate lays out
rather than anything the compiler chooses. Nix adds a reproducible *builder*,
so anyone asked to trust an `expected_mrtd` can rebuild what computed it.

## Test

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

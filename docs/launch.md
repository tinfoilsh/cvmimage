# The measured launch: `firmware/` and `compiler/`

- **`firmware/`** is what the guest executes and the state it starts from: the
  reset stubs, the guest-physical map, the ACPI tables, the zero page, the page
  tables, and on SEV-SNP the boot processor's Virtual Machine Save Area (VMSA).
  All of it is measured, except the tables that depend on how large a machine
  the guest is given (see below).
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
4 KiB reset shim that checks the host's memory map against the layouts the
image measured, fills in the end of RAM and the processor count, and enters
Linux. It accepts no memory: the loader delivers what Linux needs accepted, as
measured pages, and Linux accepts the rest itself.

## Design

At build time the compiler validates the `bzImage`, places the kernel and
initramfs, and constructs the zero page, ACPI tables, GDT, stack, command line
and identity page tables.

Everything the guest is handed is decided at build time from one placement
map, and measured, but two numbers the host chooses after the measurement is
closed: the processor count and how much RAM the guest has. Measuring either
would bind every image to one machine. The image declares two IGVM parameter
areas, one page each; a loader deposits the processor count in the first and
its memory map in the second. Each area's address, size and kind enter the
measurement; only the contents do not, and both are untrusted.

The shim (`firmware/src/shape.inc`, `madt.inc`) then:

- **matches the memory map against the image's shapes.** The image measures
  each layout QEMU's q35 gives the guests tinfoild launches (`boot::qemu_shapes`:
  all RAM below 4 GiB; split at 4 GiB; on AMD, moved past HyperTransport to
  1 TiB), each with its E820 table and EFI descriptors. The loader's map has to
  be one of them entry for entry, with only the end of one RAM entry free within
  the shape's measured bounds. Anything else terminates the guest. The shim
  copies that shape's tables and sets the end;
- **marks the units Linux accepts** in the unaccepted-memory bitmap (see Lazy
  acceptance);
- **builds the MADT** from the processor count, refusing one outside
  1..=`MAX_VCPUS`;
- jumps to `startup_64` with the zero page in `%rsi`.

On TDX it first switches from 32-bit mode to long mode on the measured page
tables, and parks application processors in the ACPI wakeup mailbox. On SEV-SNP
the measured save area starts the boot processor in long mode, and Linux brings
up the other processors itself through the GHCB AP-creation call, so only the
boot processor's save area is measured and the processor count stays out of the
measurement. The SNP shim exits to the host only to terminate, through the GHCB
MSR protocol; neither shim does port I/O.

On TDX every image page contributes to MRTD. On SEV-SNP the digest covers the
normal pages and the boot processor's VMSA.

The SNP image reaches Linux through a confidential-computing blob on the
`setup_data` chain. The record and the blob share one measured page of E820 RAM
and the record claims the whole page: Linux re-reads the chain long after boot
in `pcibios_device_add()`, and `memremap()` returns ciphertext for a page
outside the RAM map, leaving every PCI device without an MSI domain.

There is no later measured boot. No RTMR is extended, no event log is produced,
and no DICE identity is derived.

The measured FADT is hardware-reduced: there are no PM registers, no SCI
handling of power events and no `_S5`, so the guest has no ACPI power-off. A
host stops a guest by stopping QEMU. The command line uses `pci=nocrs`, which
gives the PCI root all of I/O and memory space.

## Build

Needs Rust, GNU `as`, GNU `objcopy` and GNU `objdump`.

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
| `--cmdline` | `panic=-1` | Linux command line |
| `--config-hash` | zero | TDX `MRCONFIGID` or SNP `HOST_DATA` |
| `--cbit` | `51` | SNP encryption bit |
| `--guest-svn` | `0` | SNP anti-rollback version |
| `--id-key` | none | Key signing the SNP ID block |

`no5lvl` is appended because the image uses four-level page tables.

`--config-hash` takes the whole field, hex-encoded: 32 bytes for SEV-SNP
`HOST_DATA`, 48 for TDX `MRCONFIGID`. The guest reads the SHA-256 of its
config out of it, so a TDX value is that hash followed by 16 zero bytes. A TDX
value with a nonzero tail is refused at both ends rather than ignored, since
the host chose those bytes: by this tool at build time, by the guest at boot.

The processor ceiling is 255: the MADT Local APIC structure states an 8-bit
APIC id and `0xff` is the xAPIC broadcast, so a larger count numbered two
processors the same.

The manifest is `format_version` 4. Versions 1 and 2 measured the guest's
memory and processor count; version 3 did not, but still recorded the RAM the
build was asked for (`memory_bytes`, `mmio_holes`). Version 4 drops those:
neither the guest's RAM nor its processor count is a build input, so it drops
`vcpus` and the SEV-SNP `topology` too: only the loader's memory map and
VP-count page say them. Only the `launch` object states what a report must say.

On SEV-SNP this needs a host kernel that accepts
`KVM_SEV_SNP_MEASURE_BSP_ONLY` and `-object sev-snp-guest,measure-bsp-only=on`.
Without both, KVM measures a save area per processor and the launch fails
against the published measurement rather than passing with a different count.

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

`MRCONFIGID` reaches the guest through the `tdx-guest` object's `mrconfigid`
property, base64-encoded like SEV-SNP's `host-data`. The example above sets no
`mrconfigid`, so the field is zero and a guest that verifies a config refuses
to boot.

QEMU must be built with `--enable-igvm` against libigvm 0.3 or newer. Upstream
supports IGVM for SEV, SEV-ES and SEV-SNP but not TDX, and implements
`IGVM_VHT_MEMORY_MAP` for SEV only, so a TDX host needs both added.

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
and the PCI aperture lies between them. The image measures the layouts it runs
in (`boot::qemu_shapes`), and the shim checks the loader's map is one of them,
taking only the end of RAM from it; a host that lays memory out any other way
is refused. The same bytes boot a guest of any size those layouts allow.

The measured page tables map the first 2 TiB with 1-GiB pages, whatever the
guest turns out to have, because they are measured and so cannot depend on it.
That bounds guest RAM at 2046 GiB.

## Lazy acceptance

Accepting private memory is linear in guest RAM, and done up front it is one
processor's work before the kernel starts, followed by Linux clearing all of
it again as it frees it into the page allocator. So the shims accept only what
Linux needs before its own acceptance runs, and leave the rest to Linux, which
accepts a 2-MiB unit when it first allocates from it and clears it then.

Linux finds unaccepted memory only through the EFI configuration table
`LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID`, so each image places one measured EFI
page (`firmware/src/efi.rs`) and points `boot_params.efi_info` at it. It states
an EFI boot that has already exited: a system table with no boot or runtime
services and that one table, as an OVMF guest is after `ExitBootServices` with
`CONFIG_EFI_DISABLE_RUNTIME`. The table's bitmap, one bit a 2-MiB unit, follows
the page in the image's zero pages, so it arrives accepted and clear.

What Linux needs accepted before its own acceptance works arrives accepted,
as measured zero pages the image places and the loader imports
(`boot::early_units`, read against Linux 7.0):

- the first 2 MiB unit, for the BIOS data area and, on TDX, the legacy scans of
  [0, 1 MiB);
- every unit the image places a page in, since those pages arrive accepted and
  accepting their unit again terminates the guest;
- after a RAM span that ends on a unit boundary, the next unit: Linux frees the
  initramfs without the guard it keeps after memory it accepts itself, and
  `load_unaligned_zeropad()` reads past it;
- the decompressor's own area at the top of its `init_size` buffer, where it
  moves itself, its stack, heap, page tables and boot GHCB before it can accept
  anything. Its size is read from `startup_64`'s `subl $rva(_end), %ebx`; a
  kernel without that instruction is refused. The kernel it writes out it
  accepts itself, wherever KASLR puts it.

Every other unit of RAM the shim marks in the bitmap (`mark_lazy`, from the
shape's measured RAM ranges). Once `efi_info` names a map, Linux's decompressor
picks the physical address it randomizes the kernel to from the shape's EFI
descriptors; Linux proper takes RAM from E820.

Zero pages cost launch time on SEV-SNP, where the security processor takes
about 0.55 ms a 4 KiB page even with 2 MiB launch updates; for rc.10 they are
about 13 MiB. Every page is still cleared before first use, and
`init_on_alloc` and `init_on_free` stay on. `accept_memory=eager` on the
command line makes Linux accept every marked unit at boot.

## Linux requirements

x86-64, boot protocol 2.12 or newer.

```text
CONFIG_INTEL_TDX_GUEST    CONFIG_SMP    CONFIG_ACPI    CONFIG_BLK_DEV_INITRD
CONFIG_AMD_MEM_ENCRYPT    CONFIG_SEV_GUEST                      (SEV-SNP also)
CONFIG_EFI    CONFIG_UNACCEPTED_MEMORY    CONFIG_EFI_DISABLE_RUNTIME
                                       (lazy acceptance: the EFI tables have no services)
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

A cvmimage version tag publishes `cvmc` alongside separate CPU and GPU images.
Each image has a format 1 manifest recording its kernel, initramfs, root disk,
measured command line, SNP and TDX artifact hashes, and launch measurements.
Compiler manifests retain their own format.

The `v0.15.0` release publishes `tinfoil-inference-v0.15.0-manifest.json` and
`tinfoil-inference-v0.15.0+gpu-manifest.json`, each with its own digest and
build-provenance subject. Configs pin `0.15.0@sha256:<cpu-manifest-digest>` or
`0.15.0+gpu@sha256:<gpu-manifest-digest>`. The full version identifies the
manifest and its artifacts; the base version identifies the release workflow.

ATC supplies the pinned manifest and its provenance and freshness endorsements.
The verifier checks the exact manifest digest and version, then compares its
SNP or TDX measurements with the authenticated quote. The approved config hash
remains bound through SNP `HOST_DATA` or TDX `MRCONFIGID`.

GPU artifact names include `+gpu` after the version; CPU names retain the base
version. All published artifacts have build-provenance attestations.

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

`cargo test` links the shims' own assembly into the test binary and runs it:
`firmware/src/harness.S` assembles the same `madt.inc` and `shape.inc` macros the
measured shims are built from, the test maps the pages they address at their
guest-physical addresses, and `firmware/src/shim.rs` hands them a loader's
parameters and diffs what they produce against the generators in `acpi.rs` and
`boot.rs`. Nothing in those macros is privileged, and every address they name
is this layout's own, which is what makes that possible -- and without it
assembly reaches a guest having never been executed anywhere, where a
misassembled macro is indistinguishable from a working one.

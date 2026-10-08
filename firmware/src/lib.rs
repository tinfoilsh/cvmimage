//! The measured initial state of a confidential guest: the physical map, ACPI
//! tables, zero page, page tables, reset shims, and on SEV-SNP the boot
//! processor's save area, which is the only one the launch digest takes. The kernel and initramfs are inputs; this crate decides only
//! where they sit. Two things are left out, because measuring either would bind
//! an image to a machine size: the MADT, which a shim writes from the processor
//! count the loader leaves in an unmeasured parameter page, and the E820 map
//! and accept ranges, which a shim derives from the memory map the loader
//! leaves in another.
//!
//! Serializing that state and hashing it belongs to the compiler. The split is
//! the trust boundary: these bytes are measured, the compiler's are not.

mod acpi;
pub mod boot;
mod efi;
pub mod kernel;
pub mod layout;
/// The shims' own assembly, linked into the tests that hold it to this crate.
#[cfg(any(test, feature = "harness"))]
pub mod shim;
pub mod vmsa;

use boot::{Fill, Placed, ACPI, RAM, RESERVED};
use kernel::{
    identity_map, prepare, shim, shim_owned, Fetch, FWCFG_INITRD, FWCFG_KERNEL, RESET_SHIM,
};
use layout::*;
use sha2::{Digest, Sha256};
use std::{io, path::Path};
use vmsa::{cc_blob, SNP_SHIM};

/// The measured state a guest launches with, before anything serializes it.
/// On SEV-SNP the save areas are measured too, and the compiler emits them.
pub struct Launch {
    /// Every region of the guest physical map, in ascending address order.
    pub placed: Vec<Placed>,
    /// The memory an SEV-SNP loader must have backed where this image places
    /// pages -- and nowhere else: the shim converts the rest of a guest's RAM
    /// itself, so no declaration here binds the image to a machine size.
    /// Intel TDX asks a loader for none, and leaves it empty.
    pub required_memory: Vec<boot::Region>,
    /// The measured spans the shim merges the loader's map into, and derives
    /// that E820 table and the ranges it accepts from -- for whatever machine
    /// the loader describes, not this one.
    pub spans: Vec<boot::Region>,
    /// Where the shim jumps once the map is in place.
    pub entry: u64,
    /// Measured bytes this crate authors, excluding kernel and initramfs.
    pub shim_owned: usize,
    /// The fw_cfg files an SEV-SNP loader has to serve: each one's name, size
    /// and SHA-256. Intel TDX measures what it places and fetches nothing.
    pub fw_cfg: Vec<FwCfgFile>,
}

/// A file the loader serves through fw_cfg, as it is served: the whole file,
/// of which the shim checks the part it copies against the measured digest.
pub struct FwCfgFile {
    pub name: &'static str,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// The Intel TDX map. The shim runs from the reset page, so the map covers it
/// and no loader is asked to accept the page the shim runs from.
pub fn tdx(kernel_path: &Path, initramfs_path: &Path, params: &Params) -> Result<Launch, String> {
    let p = prepare(kernel_path, initramfs_path, params)?;

    // The one authoritative map: E820, the file's pages and the accept list follow from it.
    let initramfs_len = p.initramfs.len();
    let mut placed = vec![
        // Blank: the zero page describes the map it belongs to, so its contents come last.
        Placed::measured(ZERO_PAGE, "", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(CMDLINE, "command_line", RESERVED, p.command),
        Placed::measured(ACPI_BASE, "acpi", ACPI, acpi::build()),
        Placed::parameters(PARAM_PAGE),
        Placed::parameters(PARAM_MAP_PAGE),
        Placed::measured(MAILBOX, "", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(PAGE_TABLES, "", RESERVED, identity_map(0, false)),
        Placed::measured(BSP_STACK, "", RESERVED, boot::gdt_stack()),
        Placed::measured(KERNEL_SETUP_BASE, "kernel_setup", RESERVED, p.setup.clone()),
        Placed::measured(EFI_PAGE, "efi", RESERVED, efi::page()),
        Placed::measured(KERNEL_BASE, "kernel", RAM, p.kernel),
        Placed::measured(INITRAMFS_BASE, "initramfs", RAM, p.initramfs),
        // The map covers the reset page, so the shim is never told to accept what it runs from.
        Placed::measured(RESET_ALIAS, "shim", RESERVED, vec![0u8; PAGE as usize]),
    ];
    placed.extend(params.mmio.iter().map(|(b, n)| Placed::mmio(*b, *n)));
    boot::validate(&placed, params.memory)?;
    let spans = boot::shim_spans(&placed);
    let mut zero = boot::zero_page(&p.setup, p.info, initramfs_len, ACPI_BASE, 0)?;
    efi::claim_boot(&mut zero);
    boot::fill(&mut placed, ZERO_PAGE, zero)?;
    boot::fill(
        &mut placed,
        RESET_ALIAS,
        shim(RESET_SHIM, p.entry, &spans, &[], lazy_bound(p.info))?,
    )?;
    let shim_owned = shim_owned(&placed)?;

    // Ascending GPA order: how a loader adds pages and the digest is built.
    placed.sort_by_key(|p| p.base);
    Ok(Launch {
        placed,
        required_memory: Vec::new(),
        spans,
        entry: p.entry,
        shim_owned,
        fw_cfg: Vec::new(),
    })
}

/// The AMD SEV-SNP map: firmware-owned CPUID and secrets pages, a
/// confidential-computing blob reached through setup_data, a shared alias in
/// the page tables, and a shim below the kernel rather than at the reset vector.
/// The kernel and initramfs are not placed pages: the AMD Secure Processor
/// measures a page at a time, at a cost that dominated launch, so the shim
/// fetches both through fw_cfg and holds them to digests it carries instead.
pub fn snp(kernel_path: &Path, initramfs_path: &Path, params: &Params) -> Result<Launch, String> {
    let p = prepare(kernel_path, initramfs_path, params)?;
    let setup_bytes = p.info.setup_bytes as u64;
    let fetch = [
        Fetch::of(KERNEL_BASE, setup_bytes, &p.kernel),
        Fetch::of(INITRAMFS_BASE, 0, &p.initramfs),
    ];
    let fw_cfg = vec![
        FwCfgFile {
            name: FWCFG_KERNEL,
            size: setup_bytes + p.kernel.len() as u64,
            sha256: p.file_digest,
        },
        FwCfgFile {
            name: FWCFG_INITRD,
            size: p.initramfs.len() as u64,
            sha256: Sha256::digest(&p.initramfs).into(),
        },
    ];

    // The one authoritative map, as on TDX: E820, the imported pages and the accept list.
    let initramfs_len = p.initramfs.len();
    let mut placed = vec![
        // Blank: the zero page describes the map it belongs to, so its contents come last.
        Placed::measured(ZERO_PAGE, "", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(CMDLINE, "command_line", RESERVED, p.command),
        Placed::measured(ACPI_BASE, "acpi", ACPI, acpi::build()),
        Placed::parameters(PARAM_PAGE),
        Placed::parameters(PARAM_MAP_PAGE),
        Placed::host(SNP_CPUID),
        Placed::host(SNP_SECRETS),
        Placed::measured(SNP_CC_BLOB, "cc_blob", RAM, cc_blob()),
        Placed::measured(
            PAGE_TABLES,
            "",
            RESERVED,
            identity_map(params.cbit as u64, true),
        ),
        Placed::measured(BSP_STACK, "", RESERVED, boot::gdt_stack()),
        Placed::measured(SNP_GHCB, "", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(EFI_PAGE, "efi", RESERVED, efi::page()),
        Placed::measured(SHIM_BASE, "shim", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(KERNEL_SETUP_BASE, "kernel_setup", RESERVED, p.setup.clone()),
        Placed::fetched(KERNEL_BASE, "kernel", RAM, p.kernel),
        Placed::fetched(INITRAMFS_BASE, "initramfs", RAM, p.initramfs),
    ];
    placed.extend(params.mmio.iter().map(|(b, n)| Placed::mmio(*b, *n)));
    boot::validate(&placed, params.memory)?;
    let spans = boot::shim_spans(&placed);
    // Only what this image loads. A loader converts these to private as it
    // imports them, so what this declares is that it has them backed at all;
    // the guest's own RAM is the shim's to convert, through the page state
    // changes psc.inc makes, and one image serves a guest of any size. The
    // fetched spans are the shim's too, so they are not among them.
    let mut required_memory: Vec<boot::Region> = placed
        .iter()
        .filter(|p| !matches!(p.fill, Fill::Mmio(_) | Fill::Fetched(_)))
        .map(|p| (p.base, p.span(), p.e820))
        .collect();
    required_memory.sort_unstable();
    // The setup_data chain is one measured SETUP_CC_BLOB record.
    let mut zero = boot::zero_page(&p.setup, p.info, initramfs_len, ACPI_BASE, SNP_CC_BLOB)?;
    efi::claim_boot(&mut zero);
    boot::fill(&mut placed, ZERO_PAGE, zero)?;
    let shim_page = shim(SNP_SHIM, p.entry, &spans, &fetch, lazy_bound(p.info))?;
    boot::fill(&mut placed, SHIM_BASE, shim_page)?;
    let shim_owned = shim_owned(&placed)?;

    placed.sort_by_key(|p| p.base);
    Ok(Launch {
        placed,
        required_memory,
        spans,
        entry: p.entry,
        shim_owned,
        fw_cfg,
    })
}

/// Everything below the end of the kernel's decompression is accepted by the
/// shim, since the decompressor runs before Linux's own acceptance does; past
/// it, whole 2-MiB units are Linux's to accept (see lazy.inc).
fn lazy_bound(info: boot::KernelInfo) -> u64 {
    align_up(KERNEL_BASE + info.init_size as u64, UNACCEPTED_UNIT)
}

/// Formats an io::Error with the action that failed.
pub fn io_error(action: &'static str) -> impl Fn(io::Error) -> String {
    move |e| format!("{action}: {e}")
}

//! The measured initial state of a confidential guest: the physical map, ACPI
//! tables, zero page, page tables, reset shims, and on SEV-SNP the boot
//! processor's save area, which is the only one the launch digest takes. The
//! kernel and initramfs are inputs; this crate decides only where they sit. Two things a shim finishes at boot, because measuring
//! either would bind an image to a machine size: the MADT, from the processor
//! count the loader leaves in an unmeasured parameter page, and the end of the
//! guest's RAM, from the memory map the loader leaves in another -- which has
//! to be one of the shapes this crate measured, whose tables are built here.
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

use boot::{Placed, ACPI, RAM, RESERVED};
use kernel::{identity_map, prepare, shim, shim_owned, RESET_SHIM};
use layout::*;
use std::{io, path::Path};
use vmsa::{cc_blob, SNP_SHIM};

/// The measured state a guest launches with, before anything serializes it.
/// On SEV-SNP the save areas are measured too, and the compiler emits them.
pub struct Launch {
    /// Every region of the guest physical map, in ascending address order.
    pub placed: Vec<Placed>,
    /// The memory an SEV-SNP loader must have made private before launch:
    /// what this image places, and the ranges the shim validates (`accept`).
    /// None of it depends on the guest's size: the rest of RAM Linux converts
    /// as it uses it, so no declaration here binds the image to a machine
    /// size. Intel TDX asks a loader for none, and leaves it empty.
    pub required_memory: Vec<boot::Region>,
    /// Every span this image places at a fixed address.
    pub spans: Vec<boot::Region>,
    /// The memory shapes the image runs in, as the shapes page measures them.
    pub shapes: Vec<boot::Shape>,
    /// Below this, the shim accepts all of the RAM the image did not place;
    /// past it, Linux accepts what it uses but for the units the image places
    /// in (`boot::span_units`).
    pub lazy: u64,
    /// The ranges the shim accepts (`boot::shim_accept`).
    pub accept: Vec<(u64, u64)>,
    /// Where the shim jumps once the map is in place.
    pub entry: u64,
    /// Measured bytes this crate authors, excluding kernel and initramfs.
    pub shim_owned: usize,
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
        Placed::measured(PAGE_TABLES, "", RESERVED, identity_map(0)),
        Placed::measured(BSP_STACK, "", RESERVED, boot::gdt_stack()),
        Placed::measured(
            SHAPES_PAGE,
            "shapes",
            RESERVED,
            vec![0u8; SHAPES_SIZE as usize],
        ),
        Placed::measured(KERNEL_SETUP_BASE, "kernel_setup", RESERVED, p.setup.clone()),
        Placed::measured(EFI_PAGE, "efi", RESERVED, efi::page()),
        Placed::measured(KERNEL_BASE, "kernel", RAM, p.kernel),
        Placed::measured(INITRAMFS_BASE, "initramfs", RAM, p.initramfs),
        // The map covers the reset page, so the shim is never told to accept what it runs from.
        Placed::measured(RESET_ALIAS, "shim", RESERVED, vec![0u8; PAGE as usize]),
    ];
    boot::validate(&placed)?;
    let spans = boot::shim_spans(&placed);
    let mut zero = boot::zero_page(&p.setup, p.info, initramfs_len, ACPI_BASE, 0)?;
    efi::claim_boot(&mut zero);
    boot::fill(&mut placed, ZERO_PAGE, zero)?;
    let (shapes, lazy, accept) = memory(&mut placed, &spans, p.info, false)?;
    let shim_page = shim(RESET_SHIM, p.entry, shapes.len(), lazy, &accept)?;
    boot::fill(&mut placed, RESET_ALIAS, shim_page)?;
    let shim_owned = shim_owned(&placed)?;

    // Ascending GPA order: how a loader adds pages and the digest is built.
    placed.sort_by_key(|p| p.base);
    Ok(Launch {
        placed,
        required_memory: Vec::new(),
        spans,
        shapes,
        lazy,
        accept,
        entry: p.entry,
        shim_owned,
    })
}

/// The AMD SEV-SNP map: firmware-owned CPUID and secrets pages, a
/// confidential-computing blob reached through setup_data, and a shim below
/// the kernel rather than at the reset vector.
pub fn snp(kernel_path: &Path, initramfs_path: &Path, params: &Params) -> Result<Launch, String> {
    let p = prepare(kernel_path, initramfs_path, params)?;

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
        Placed::measured(PAGE_TABLES, "", RESERVED, identity_map(params.cbit as u64)),
        Placed::measured(BSP_STACK, "", RESERVED, boot::gdt_stack()),
        Placed::measured(
            SHAPES_PAGE,
            "shapes",
            RESERVED,
            vec![0u8; SHAPES_SIZE as usize],
        ),
        Placed::measured(EFI_PAGE, "efi", RESERVED, efi::page()),
        Placed::measured(SHIM_BASE, "shim", RESERVED, vec![0u8; PAGE as usize]),
        Placed::measured(KERNEL_SETUP_BASE, "kernel_setup", RESERVED, p.setup.clone()),
        Placed::measured(KERNEL_BASE, "kernel", RAM, p.kernel),
        Placed::measured(INITRAMFS_BASE, "initramfs", RAM, p.initramfs),
    ];
    boot::validate(&placed)?;
    let spans = boot::shim_spans(&placed);
    // The setup_data chain is one measured SETUP_CC_BLOB record.
    let mut zero = boot::zero_page(&p.setup, p.info, initramfs_len, ACPI_BASE, SNP_CC_BLOB)?;
    efi::claim_boot(&mut zero);
    boot::fill(&mut placed, ZERO_PAGE, zero)?;
    let (shapes, lazy, accept) = memory(&mut placed, &spans, p.info, true)?;
    let shim_page = shim(SNP_SHIM, p.entry, shapes.len(), lazy, &accept)?;
    boot::fill(&mut placed, SHIM_BASE, shim_page)?;
    let shim_owned = shim_owned(&placed)?;
    // What this image loads, which a loader converts to private as it imports
    // it, and the RAM below the lazy bound, which it converts because this
    // asks it to: the shim validates that and asks the host for nothing. Past
    // the bound Linux converts what it uses, so one image serves a guest of
    // any size.
    let mut required_memory: Vec<boot::Region> = spans
        .iter()
        .map(|(lo, hi, kind)| (*lo, hi - lo, *kind))
        .chain(accept.iter().map(|(lo, hi)| (*lo, hi - lo, RAM)))
        .collect();
    required_memory.sort_unstable();

    placed.sort_by_key(|p| p.base);
    Ok(Launch {
        placed,
        required_memory,
        spans,
        shapes,
        lazy,
        accept,
        entry: p.entry,
        shim_owned,
    })
}

/// Everything below the end of the kernel's decompression is accepted by the
/// shim, since the decompressor runs before Linux's own acceptance does; past
/// it, whole 2-MiB units are Linux's to accept (see shape.inc).
fn lazy_bound(info: boot::KernelInfo) -> u64 {
    align_up(KERNEL_BASE + info.init_size as u64, UNACCEPTED_UNIT)
}

/// The shapes, the lazy bound and the ranges the shim accepts, as `memory`
/// works them out.
type Memory = (Vec<boot::Shape>, u64, Vec<(u64, u64)>);

/// The memory side of a launch: the shapes the guest's map may take, measured
/// into the shapes page; the lazy bound; and the ranges the shim accepts.
fn memory(
    placed: &mut [Placed],
    spans: &[boot::Region],
    info: boot::KernelInfo,
    amd: bool,
) -> Result<Memory, String> {
    let lazy = lazy_bound(info);
    let shapes = boot::qemu_shapes(amd, boot::least_memory(spans, lazy));
    boot::fill(
        placed,
        SHAPES_PAGE,
        boot::shapes_page(&shapes, spans, lazy)?,
    )?;
    let accept = boot::shim_accept(spans, lazy);
    Ok((shapes, lazy, accept))
}

/// Formats an io::Error with the action that failed.
pub fn io_error(action: &'static str) -> impl Fn(io::Error) -> String {
    move |e| format!("{action}: {e}")
}

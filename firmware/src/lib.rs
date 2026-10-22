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
    /// what this image places, its zero pages included. None of it depends on
    /// the guest's size: the rest of RAM Linux converts as it uses it, so no
    /// declaration here binds the image to a machine size. Intel TDX asks a
    /// loader for none, and leaves it empty.
    pub required_memory: Vec<boot::Region>,
    /// Every span this image places at a fixed address.
    pub spans: Vec<boot::Region>,
    /// The memory shapes the image runs in, as the shapes page measures them.
    pub shapes: Vec<boot::Shape>,
    /// The 2 MiB units that arrive accepted (`boot::early_units`), as the
    /// image's pages or its zero pages; Linux accepts the rest of RAM as it
    /// uses it.
    pub early: Vec<(u64, u64)>,
    /// The RAM delivered as measured zero pages (`boot::zero_ranges`), so
    /// that it arrives accepted.
    pub zeros: Vec<(u64, u64)>,
    /// Where the shim jumps once the map is in place.
    pub entry: u64,
    /// Measured bytes this crate authors, excluding kernel and initramfs.
    pub shim_owned: usize,
}

/// The Intel TDX map. The shim runs from the reset page, so the map covers it.
pub fn tdx(kernel_path: &Path, initramfs_path: &Path, params: &Params) -> Result<Launch, String> {
    let p = prepare(kernel_path, initramfs_path, params)?;

    // The one authoritative map: E820 and the file's pages follow from it.
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
        // The map covers the reset page, so it is measured like the rest.
        Placed::measured(RESET_ALIAS, "shim", RESERVED, vec![0u8; PAGE as usize]),
    ];
    boot::validate(&placed)?;
    let spans = boot::shim_spans(&placed);
    let mut zero = boot::zero_page(&p.setup, p.info, initramfs_len, ACPI_BASE, 0)?;
    efi::claim_boot(&mut zero);
    boot::fill(&mut placed, ZERO_PAGE, zero)?;
    let (shapes, early, zeros) = memory(&mut placed, &spans, p.info, false)?;
    let shim_page = shim(RESET_SHIM, p.entry, shapes.len())?;
    boot::fill(&mut placed, RESET_ALIAS, shim_page)?;
    let shim_owned = shim_owned(&placed)?;
    // Placed after the shapes and the authored-bytes count, both of which
    // they follow from rather than feed.
    placed.extend(zeros.iter().map(|(lo, hi)| Placed::zero(*lo, hi - lo)));

    // Ascending GPA order: how a loader adds pages and the digest is built.
    placed.sort_by_key(|p| p.base);
    Ok(Launch {
        placed,
        required_memory: Vec::new(),
        spans,
        shapes,
        early,
        zeros,
        entry: p.entry,
        shim_owned,
    })
}

/// The AMD SEV-SNP map: firmware-owned CPUID and secrets pages, a
/// confidential-computing blob reached through setup_data, and a shim below
/// the kernel rather than at the reset vector.
pub fn snp(kernel_path: &Path, initramfs_path: &Path, params: &Params) -> Result<Launch, String> {
    let p = prepare(kernel_path, initramfs_path, params)?;

    // The one authoritative map, as on TDX: E820 and the imported pages.
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
    let (shapes, early, zeros) = memory(&mut placed, &spans, p.info, true)?;
    let shim_page = shim(SNP_SHIM, p.entry, shapes.len())?;
    boot::fill(&mut placed, SHIM_BASE, shim_page)?;
    let shim_owned = shim_owned(&placed)?;
    // Placed after the shapes and the authored-bytes count, both of which
    // they follow from rather than feed.
    placed.extend(zeros.iter().map(|(lo, hi)| Placed::zero(*lo, hi - lo)));
    // What this image loads, its zero pages included, which a loader converts
    // to private as it imports it. Past the bound Linux converts what it uses,
    // so one image serves a guest of any size.
    let mut required_memory: Vec<boot::Region> = spans
        .iter()
        .map(|(lo, hi, kind)| (*lo, hi - lo, *kind))
        .chain(zeros.iter().map(|(lo, hi)| (*lo, hi - lo, RAM)))
        .collect();
    required_memory.sort_unstable();

    placed.sort_by_key(|p| p.base);
    Ok(Launch {
        placed,
        required_memory,
        spans,
        shapes,
        early,
        zeros,
        entry: p.entry,
        shim_owned,
    })
}

/// The shapes, the early units and the zero ranges, as `memory` works them out.
type Memory = (Vec<boot::Shape>, Vec<(u64, u64)>, Vec<(u64, u64)>);

/// The memory side of a launch: the units that arrive accepted, the shapes
/// the guest's map may take, measured into the shapes page, and the RAM of
/// those units the image fills with zero pages.
fn memory(
    placed: &mut [Placed],
    spans: &[boot::Region],
    info: boot::KernelInfo,
    amd: bool,
) -> Result<Memory, String> {
    let early = boot::early_units(spans, boot::decompressor_area(info));
    let shapes = boot::qemu_shapes(amd, boot::least_memory(spans, &early));
    boot::fill(
        placed,
        SHAPES_PAGE,
        boot::shapes_page(&shapes, spans, &early)?,
    )?;
    let zeros = boot::zero_ranges(spans, &early);
    // The bitmap must arrive zero, which the zero pages make it.
    let bitmap = (
        UNACCEPTED_BITMAP,
        UNACCEPTED_BITMAP + UNACCEPTED_BITMAP_SIZE,
    );
    if !zeros
        .iter()
        .any(|(lo, hi)| *lo <= bitmap.0 && bitmap.1 <= *hi)
    {
        return Err("the unaccepted bitmap lies outside the zero pages".into());
    }
    Ok((shapes, early, zeros))
}

/// Formats an io::Error with the action that failed.
pub fn io_error(action: &'static str) -> impl Fn(io::Error) -> String {
    move |e| format!("{action}: {e}")
}

//! The shims' own assembly, run in this process.
//!
//! `madt.inc` and `map.inc` execute no privileged instruction, and the only
//! addresses they name are this layout's own, so the macros the measured shims
//! are built from link into a test binary, run there with those pages mapped
//! where a guest has them, and are held to the generators in `acpi.rs` and
//! `boot.rs` that state what they must produce.
//!
//! Without this, assembly reaches a guest having never been executed anywhere:
//! a test that re-implements what a macro was supposed to do passes just as
//! green for a macro that was misassembled, or that nothing jumps to.

use crate::boot::{self, Region};
use crate::kernel::data_block;
use crate::layout::*;
use std::sync::{Mutex, MutexGuard, OnceLock};

extern "C" {
    fn harness_regions() -> u64;
    fn harness_e820(zero: *mut u8, memory: u64) -> u64;
    fn harness_accept_walk(memory: u64) -> u64;
    fn harness_madt_wakeup() -> u64;
    fn harness_madt_bare() -> u64;
    static mut harness_shim_data: [u8; SHIM_DATA_SIZE as usize];
    static mut harness_ranges: [u64; 512];
    static harness_madt_template: [u8; MADT_HEADER_LEN as usize];
}

// The pages the shims address by guest-physical address: the ACPI page they
// write the MADT into, the two the loader fills, and the two they build their
// region lists in.
const _: () = assert!(PARAM_PAGE == ACPI_BASE + PAGE && PARAM_MAP_PAGE == ACPI_BASE + 2 * PAGE);
const _: () = assert!(SHIM_REGIONS_END - SHIM_HOST_REGIONS == 2 * PAGE);

/// mmap(2) by syscall, so running the shim costs the crate no dependency.
fn map_pages(base: u64, len: u64) {
    // PROT_READ | PROT_WRITE, and MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE.
    let mapped: i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") 9i64 => mapped,
            in("rdi") base,
            in("rsi") len,
            in("rdx") 0x3i64,
            in("r10") 0x10_0022i64,
            in("r8") -1i64,
            in("r9") 0i64,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    assert_eq!(
        mapped, base as i64,
        "the guest-physical pages the shim writes could not be mapped at {base:#x}; \
         vm.mmap_min_addr may be above it"
    );
}

fn map_low_pages() {
    map_pages(ACPI_BASE, 3 * PAGE);
    map_pages(SHIM_HOST_REGIONS, SHIM_REGIONS_END - SHIM_HOST_REGIONS);
}

/// The shim, with the pages it addresses mapped and nothing else running
/// against them.
pub struct Shim(#[allow(dead_code)] MutexGuard<'static, ()>);

pub fn shim() -> Shim {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = LOCK.get_or_init(|| {
        map_low_pages();
        Mutex::new(())
    });
    // A test that failed mid-way left the pages dirty, not the lock unusable.
    Shim(lock.lock().unwrap_or_else(|e| e.into_inner()))
}

fn page(base: u64) -> &'static mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(base as *mut u8, PAGE as usize) }
}

impl Shim {
    /// The processor count an untrusted loader leaves in its parameter page.
    pub fn loader_vcpus(&self, count: u32) -> &Self {
        let p = page(PARAM_PAGE);
        p.fill(0);
        p[..4].copy_from_slice(&count.to_le_bytes());
        self
    }

    /// The memory map an untrusted loader leaves in its parameter page, as
    /// IGVM_VHS_MEMORY_MAP_ENTRY: a page number, a page count and a type.
    pub fn loader_memory_map(&self, entries: &[(u64, u64, u16)]) -> &Self {
        let p = page(PARAM_MAP_PAGE);
        p.fill(0);
        for (n, (start, pages, kind)) in entries.iter().enumerate() {
            let at = n * MAP_ENTRY_LEN as usize;
            p[at..at + 8].copy_from_slice(&start.to_le_bytes());
            p[at + 8..at + 16].copy_from_slice(&pages.to_le_bytes());
            p[at + 16..at + 18].copy_from_slice(&kind.to_le_bytes());
        }
        self
    }

    /// A QEMU q35 memory map for a guest of `ram`, which is what the loader
    /// deposits: everything below the aperture, and the rest above 4 GiB.
    pub fn loader_ram(&self, ram: u64) -> &Self {
        // hw/i386/pc.c: a guest this size or larger restacks above 4 GiB.
        let low = if ram >= Q35_SPLIT { Q35_LOWMEM } else { ram };
        let mut entries = vec![(0, low / PAGE, MAP_TYPE_MEMORY as u16)];
        if ram > low {
            entries.push((FOUR_GIB / PAGE, (ram - low) / PAGE, MAP_TYPE_MEMORY as u16));
        }
        self.loader_memory_map(&entries)
    }

    /// The measured data block the shims carry in their own page.
    pub fn data(&self, entry: u64, spans: &[Region]) -> &Self {
        let block = data_block(entry, spans).unwrap();
        let data = unsafe { &mut *std::ptr::addr_of_mut!(harness_shim_data) };
        data.fill(0);
        data[..block.len()].copy_from_slice(&block);
        self
    }

    /// The regions the shim merges the loader's map into its own, and the top
    /// of guest RAM; None where it refuses the map and terminates.
    pub fn regions(&self) -> Option<(u64, Vec<Region>)> {
        let top = unsafe { harness_regions() };
        if top == 0 {
            return None;
        }
        let list = unsafe {
            std::slice::from_raw_parts(
                SHIM_REGIONS as *const u8,
                (SHIM_REGIONS_END - SHIM_REGIONS) as usize,
            )
        };
        let mut out = Vec::new();
        let mut at = 0usize;
        loop {
            let word = |i: usize| u64::from_le_bytes(list[at + i..at + i + 8].try_into().unwrap());
            let (lo, hi) = (word(0), word(SPAN_HI as usize));
            if lo == 0 && hi == 0 {
                return Some((top, out));
            }
            out.push((lo, hi, word(SPAN_KIND as usize) as u32));
            at += SPAN_LEN as usize;
            assert!(
                at + SPAN_LEN as usize <= list.len(),
                "the merge overran its buffer"
            );
        }
    }

    /// The E820 map the shim writes into a zero page for a guest of `memory`.
    pub fn e820(&self, memory: u64) -> Option<Vec<Region>> {
        let mut zero = vec![0u8; PAGE as usize];
        match unsafe { harness_e820(zero.as_mut_ptr(), memory) } {
            0 => None,
            _ => Some(boot::read_e820(&zero)),
        }
    }

    /// The ranges the shim asks PVALIDATE or TDG.MEM.PAGE.ACCEPT for, in the
    /// order it asks for them.
    pub fn accept_ranges(&self, memory: u64) -> Vec<(u64, u64)> {
        let count = unsafe { harness_accept_walk(memory) } as usize;
        let ranges = unsafe { &*std::ptr::addr_of!(harness_ranges) };
        assert!(2 * count <= ranges.len(), "the walk overran its buffer");
        (0..count)
            .map(|n| (ranges[2 * n], ranges[2 * n + 1]))
            .collect()
    }

    /// The MADT the shim writes into the ACPI page, or None where it refuses
    /// the processor count and terminates.
    pub fn madt(&self, wakeup: bool) -> Option<Vec<u8>> {
        let table = &mut page(ACPI_BASE)[ACPI_MADT as usize..];
        table.fill(0);
        let built = unsafe {
            if wakeup {
                harness_madt_wakeup()
            } else {
                harness_madt_bare()
            }
        };
        if built == 0 {
            return None;
        }
        let table = &page(ACPI_BASE)[ACPI_MADT as usize..];
        let len = u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize;
        assert!(len <= table.len(), "the table the shim wrote left its page");
        Some(table[..len].to_vec())
    }

    /// The fixed header the shim copies, which every shim page carries.
    pub fn madt_template(&self) -> &'static [u8] {
        unsafe { &*std::ptr::addr_of!(harness_madt_template) }
    }
}

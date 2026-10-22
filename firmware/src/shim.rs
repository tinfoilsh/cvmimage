//! The shims' own assembly, run in this process.
//!
//! `madt.inc` and `shape.inc` execute no privileged instruction, and the only
//! addresses they name are this layout's own, so the macros the measured shims
//! are built from link into a test binary, run there with those pages mapped
//! where a guest has them, and are held to the generators in `acpi.rs` and
//! `boot.rs` that state what they must produce.
//!
//! Without this, assembly reaches a guest having never been executed anywhere:
//! a test that re-implements what a macro was supposed to do passes just as
//! green for a macro that was misassembled, or that nothing jumps to.

use crate::boot::{self, Region, Shape};
use crate::layout::*;
use std::sync::{Mutex, MutexGuard, OnceLock};

extern "C" {
    fn harness_boot_map(zero: *mut u8) -> u64;
    fn harness_madt_wakeup() -> u64;
    fn harness_madt_bare() -> u64;
    static harness_madt_template: [u8; MADT_TEMPLATE_LEN as usize];
}

// The pages the shims address by guest-physical address: the ACPI page they
// write the MADT into and the two the loader fills.
const _: () = assert!(PARAM_PAGE == ACPI_BASE + PAGE && PARAM_MAP_PAGE == ACPI_BASE + 2 * PAGE);

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
    map_pages(SHAPES_PAGE, SHAPES_SIZE);
    // The EFI page whose map and unaccepted table the shim completes, and the
    // bitmap after it.
    map_pages(EFI_PAGE, PAGE + UNACCEPTED_BITMAP_SIZE);
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

/// One of those pages. It is raw because the same bytes are read back through
/// another pointer, and two live references to them would be a rule broken for
/// no gain.
fn page(base: u64) -> *mut u8 {
    base as *mut u8
}

fn fill(base: u64, at: u64, bytes: &[u8]) {
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), page(base).add(at as usize), bytes.len())
    }
}

fn zero(base: u64, at: u64, len: u64) {
    unsafe { std::ptr::write_bytes(page(base).add(at as usize), 0, len as usize) }
}

fn read(base: u64, at: u64, len: u64) -> Vec<u8> {
    let mut v = vec![0u8; len as usize];
    unsafe { std::ptr::copy_nonoverlapping(page(base).add(at as usize), v.as_mut_ptr(), v.len()) }
    v
}

/// What the boot path left behind for one map: the top of RAM it found, the
/// tables it wrote, and each unit it left Linux to accept.
#[derive(Debug)]
pub struct BootMap {
    pub top: u64,
    pub e820: Vec<Region>,
    /// Each EFI descriptor as (type, start, pages, attribute), the measured
    /// one first, and the size efi_info states.
    pub efi: Vec<(u32, u64, u64, u64)>,
    pub efi_size: u32,
    pub units: Vec<u64>,
    pub unaccepted_size: u64,
}

impl Shim {
    /// The processor count an untrusted loader leaves in its parameter page.
    pub fn loader_vcpus(&self, count: u32) -> &Self {
        zero(PARAM_PAGE, 0, PAGE);
        fill(PARAM_PAGE, 0, &count.to_le_bytes());
        self
    }

    /// The memory map an untrusted loader leaves in its parameter page, as
    /// IGVM_VHS_MEMORY_MAP_ENTRY: a page number, a page count and a type.
    pub fn loader_memory_map(&self, entries: &[(u64, u64, u16)]) -> &Self {
        // The shim reads a bounded run out of one page; writing past it would
        // corrupt whatever the harness mapped next.
        assert!(
            (entries.len() as u64 + 1) * MAP_ENTRY_LEN <= PAGE,
            "memory map does not fit the parameter page"
        );
        zero(PARAM_MAP_PAGE, 0, PAGE);
        for (n, (start, pages, kind)) in entries.iter().enumerate() {
            let at = n as u64 * MAP_ENTRY_LEN;
            fill(PARAM_MAP_PAGE, at, &start.to_le_bytes());
            fill(PARAM_MAP_PAGE, at + MAP_ENTRY_PAGES, &pages.to_le_bytes());
            fill(PARAM_MAP_PAGE, at + MAP_ENTRY_TYPE, &kind.to_le_bytes());
        }
        self
    }

    /// The map a loader states for a guest of `shape` whose variable RAM
    /// ends at `end`, which need not be a whole unit.
    pub fn loader_shape(&self, shape: &Shape, end: u64) -> &Self {
        let entries: Vec<_> = shape
            .map(end)
            .iter()
            .map(|(lo, len, kind)| (lo / PAGE, len / PAGE, *kind))
            .collect();
        self.loader_memory_map(&entries)
    }

    /// The shapes page an image carries, byte for byte.
    pub fn image(&self, shapes_page: &[u8]) -> &Self {
        fill(SHAPES_PAGE, 0, shapes_page);
        self
    }

    /// The boot path run against the loader's map, from an image's measured
    /// EFI page and zero page; None where it refuses the map and terminates.
    pub fn boot_map(&self, efi_page: &[u8], zero_page: &[u8]) -> Option<BootMap> {
        fill(EFI_PAGE, 0, efi_page);
        // Accepted RAM, which is where the bitmap lives, arrives zeroed.
        zero(UNACCEPTED_BITMAP, 0, UNACCEPTED_BITMAP_SIZE);
        let mut zero_page = zero_page.to_vec();
        let top = unsafe { harness_boot_map(zero_page.as_mut_ptr()) };
        if top == 0 {
            return None;
        }
        let efi_size = u32::from_le_bytes(
            zero_page[BP_EFI_MEMMAP_SIZE as usize..][..4]
                .try_into()
                .unwrap(),
        );
        let map = read(EFI_PAGE, EFI_MEMMAP, efi_size as u64);
        let word = |at: usize| u64::from_le_bytes(map[at..at + 8].try_into().unwrap());
        let efi = (0..efi_size as usize / EFI_MEMDESC_SIZE as usize)
            .map(|n| {
                let at = n * EFI_MEMDESC_SIZE as usize;
                (word(at) as u32, word(at + 8), word(at + 24), word(at + 32))
            })
            .collect();
        let bitmap = read(UNACCEPTED_BITMAP, 0, UNACCEPTED_BITMAP_SIZE);
        let units = (0..bitmap.len() as u64 * 8)
            .filter(|n| bitmap[*n as usize / 8] >> (n % 8) & 1 == 1)
            .collect();
        let unaccepted_size = u64::from_le_bytes(read(UNACCEPTED_TABLE, 16, 8).try_into().unwrap());
        Some(BootMap {
            top,
            e820: boot::read_e820(&zero_page),
            efi,
            efi_size,
            units,
            unaccepted_size,
        })
    }

    /// The MADT the shim writes into the ACPI page, or None where it refuses
    /// the processor count and terminates.
    pub fn madt(&self, wakeup: bool) -> Option<Vec<u8>> {
        zero(ACPI_BASE, ACPI_MADT, PAGE - ACPI_MADT);
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
        let len = u32::from_le_bytes(read(ACPI_BASE, ACPI_MADT + 4, 4).try_into().unwrap()) as u64;
        assert!(
            ACPI_MADT + len <= PAGE,
            "the table the shim wrote left its page"
        );
        Some(read(ACPI_BASE, ACPI_MADT, len))
    }

    /// The fixed header the shim copies, which every shim page carries.
    pub fn madt_template(&self) -> &'static [u8] {
        unsafe { &*std::ptr::addr_of!(harness_madt_template) }
    }
}

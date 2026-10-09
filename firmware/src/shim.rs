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

// As harness.S sizes them: two words a range, and two an entry.
const HARNESS_RANGES: usize = 256;
const HARNESS_PSC_ENTRIES: usize = 4096;
const HARNESS_POWER_WRITES: usize = 5;

extern "C" {
    fn harness_regions() -> u64;
    fn harness_e820(zero: *mut u8, memory: u64) -> u64;
    fn harness_accept_walk(memory: u64) -> u64;
    fn harness_psc_range(lo: u64, hi: u64, host: u64) -> u64;
    fn harness_madt_wakeup() -> u64;
    fn harness_madt_bare() -> u64;
    fn harness_power(tdx: u64, fail_at: u64, module_failure: u64) -> u64;
    static harness_power_count: u64;
    static harness_power_requests: [[u64; 8]; HARNESS_POWER_WRITES];
    static mut harness_shim_data: [u8; SHIM_DATA_SIZE as usize];
    static mut harness_ranges: [u64; 2 * HARNESS_RANGES];
    static mut harness_psc_entries: [u64; 2 * HARNESS_PSC_ENTRIES];
    static harness_psc_count: u64;
    static harness_psc_calls: u64;
    static harness_psc_bytes: u64;
    static harness_psc_lost: u64;
    static harness_madt_template: [u8; MADT_TEMPLATE_LEN as usize];
}

/// What the host the shim is run against does with a batch, as harness.S
/// numbers them. The first three are hosts the shim has to finish against;
/// the rest are hosts it has to refuse.
#[derive(Debug, Clone, Copy)]
pub enum Host {
    /// Converts every entry of a batch in one exit.
    Whole = 0,
    /// Converts one entry an exit, which is a host within its rights.
    OneAtATime = 1,
    /// Converts nothing, which the shim has to refuse rather than retry.
    Nothing = 2,
    /// Converts one page of an entry, reporting it in the cursor the entry
    /// carries, and the rest of that entry when it is asked again. Also a
    /// host within its rights, and the reason progress is not the entry
    /// index alone.
    PartOfAnEntry = 3,
    /// Winds the entry cursor back, which is the one way the protocol does
    /// not let it move.
    Backwards = 4,
    /// Answers with an end_entry past the batch the shim described, naming an
    /// entry the shim never wrote.
    PastTheBatch = 5,
    /// Reports the request as not taken, in the block's own fields.
    Refuses = 6,
    /// Raises end_entry to one a full batch writes, past the shorter batch
    /// the shim described.
    RaisesTheEnd = 7,
}

/// The request the shim left in the block for a host to read: what it asks
/// for, which fields of the block it says it filled in, and the header of the
/// descriptor it points at.
#[derive(Debug, PartialEq, Eq)]
pub struct Ghcb {
    pub exit_code: u64,
    pub exit_info_1: u64,
    pub exit_info_2: u64,
    pub scratch: u64,
    pub valid: [u8; 16],
    pub usage: u32,
    pub protocol: u16,
    /// The dword the page state change header reserves.
    pub reserved: u32,
}

/// One page state change entry: the page it names, how much of it the entry
/// covers, and which entry of its own batch it was.
#[derive(Debug, PartialEq, Eq)]
pub struct Psc {
    pub base: u64,
    pub size: u64,
    pub index: u64,
}

/// What the shim asked a host for over one range.
pub struct PscWalk {
    /// The first HARNESS_PSC_ENTRIES of them, in the order they were asked for.
    pub entries: Vec<Psc>,
    /// How many there were, which for a large guest is more than were recorded.
    pub count: u64,
    /// What they covered between them.
    pub bytes: u64,
    /// How many exits it took.
    pub calls: u64,
    /// Whether the range its caller holds across the conversion came back the
    /// range it was.
    pub held: bool,
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
    // The block, at the address the shim writes it through rather than the one
    // it names to the host.
    map_pages(GHCB_ALIAS, PAGE);
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

impl Shim {
    pub fn power(&self, tdx: bool, fail_at: u64, module_failure: bool) -> (bool, Vec<[u64; 8]>) {
        unsafe {
            let success = harness_power(tdx.into(), fail_at, module_failure.into()) != 0;
            let count = harness_power_count as usize;
            assert!(count <= HARNESS_POWER_WRITES);
            (success, harness_power_requests[..count].to_vec())
        }
    }

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
        let list = read(SHIM_REGIONS, 0, SHIM_REGIONS_END - SHIM_REGIONS);
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
        let mut page = vec![0u8; PAGE as usize];
        match unsafe { harness_e820(page.as_mut_ptr(), memory) } {
            0 => None,
            _ => Some(boot::read_e820(&page)),
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

    /// The block filled with a byte no field of a request holds, so that a
    /// field the shim leaves alone is not read back as a zero it never wrote.
    fn poison(&self) {
        unsafe { std::ptr::write_bytes(page(GHCB_ALIAS), 0xff, PAGE as usize) }
    }

    /// The block as a host would read it after the last exit the shim made.
    pub fn ghcb(&self) -> Ghcb {
        let word = |at: u64| u64::from_le_bytes(read(GHCB_ALIAS, at, 8).try_into().unwrap());
        let half = |at: u64| u32::from_le_bytes(read(GHCB_ALIAS, at, 4).try_into().unwrap());
        Ghcb {
            exit_code: word(GHCB_SW_EXIT_CODE),
            exit_info_1: word(GHCB_SW_EXIT_INFO_1),
            exit_info_2: word(GHCB_SW_EXIT_INFO_2),
            scratch: word(GHCB_SW_SCRATCH),
            valid: read(GHCB_ALIAS, GHCB_VALID_BITMAP, 16).try_into().unwrap(),
            usage: half(GHCB_USAGE),
            protocol: u16::from_le_bytes(
                read(GHCB_ALIAS, GHCB_PROTOCOL_VERSION, 2)
                    .try_into()
                    .unwrap(),
            ),
            // The dword the header leaves between end_entry and the entries.
            reserved: half(GHCB_SHARED_BUFFER + PSC_END_ENTRY + 2),
        }
    }

    /// Whether the range the caller of `psc_range` holds survived it, which a
    /// refused host leaves no walk to read it from.
    pub fn held(&self) -> bool {
        unsafe { harness_psc_lost == 0 }
    }

    /// The page state changes the shim asks for to make `[lo, hi)` private, in
    /// the order it asks for them; None where it refused the host.
    pub fn psc(&self, lo: u64, hi: u64, host: Host) -> Option<PscWalk> {
        self.poison();
        if unsafe { harness_psc_range(lo, hi, host as u64) } == 0 {
            return None;
        }
        let count = unsafe { harness_psc_count };
        let entries = unsafe { &*std::ptr::addr_of!(harness_psc_entries) };
        let recorded = (count as usize).min(entries.len() / 2);
        let out = (0..recorded)
            .map(|n| {
                let word = entries[2 * n];
                // Bits 51:12 are the page, 55:52 the operation, 56 the size.
                assert_eq!(
                    word >> PSC_ENTRY_LARGE >> 1,
                    0,
                    "an entry set a bit above the size"
                );
                assert_eq!(
                    word >> PSC_ENTRY_PRIVATE & 0xf,
                    1,
                    "an entry asked for something other than private"
                );
                assert_eq!(word & (PAGE - 1), 0, "an entry named part of a page");
                Psc {
                    base: word & !(0xfff << PSC_ENTRY_PRIVATE | (PAGE - 1)),
                    size: if word >> PSC_ENTRY_LARGE & 1 == 1 {
                        0x200000
                    } else {
                        PAGE
                    },
                    index: entries[2 * n + 1],
                }
            })
            .collect();
        Some(PscWalk {
            entries: out,
            count,
            bytes: unsafe { harness_psc_bytes },
            calls: unsafe { harness_psc_calls },
            held: self.held(),
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

//! The EFI tables an image hands Linux so that it accepts guest RAM itself.
//!
//! Upstream Linux learns which memory is unaccepted only from the EFI
//! configuration table LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID, found through
//! boot_params.efi_info (arch/x86/boot/compressed/mem.c, drivers/firmware/efi).
//! So the image states an EFI boot that has already exited, with no boot or
//! runtime services and this one table, as an OVMF guest is after
//! ExitBootServices with CONFIG_EFI_DISABLE_RUNTIME, which this kernel sets.
//! Everything here is fixed and measured. At boot a shim writes only what
//! depends on the RAM the guest has: the bitmap's size and bits, and the
//! memory map descriptors of the shape the guest's map is, copied from the
//! shapes page with the last one's end set (shape.inc).

use crate::boot::{put32, put64};
use crate::layout::*;

const SYSTAB_SIGNATURE: u64 = 0x5453_5953_2049_4249;
const SYSTAB_REVISION: u32 = 2 << 16 | 10;
const SYSTAB_HEADER_SIZE: u32 = 120;
const SYSTAB_FW_VENDOR: usize = 24;
const SYSTAB_NR_TABLES: usize = 104;
const SYSTAB_TABLES: usize = 112;
// d5d1de3c-105c-44f9-9ea9-bcef98120031, as Linux lays a GUID out in memory.
const UNACCEPTED_GUID: [u8; 16] = [
    0x3c, 0xde, 0xd1, 0xd5, 0x5c, 0x10, 0xf9, 0x44, 0x9e, 0xa9, 0xbc, 0xef, 0x98, 0x12, 0x00, 0x31,
];
const UNACCEPTED_VERSION: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_MEMDESC_VERSION: u32 = 1;
const EL64: u32 = u32::from_le_bytes(*b"EL64");

/// The measured page: system table, its one configuration table, the vendor
/// string, a memory map whose one descriptor covers this page, and the header
/// of the unaccepted table whose bitmap starts on the next page.
pub fn page() -> Vec<u8> {
    let mut v = vec![0u8; PAGE as usize];
    put64(&mut v, 0, SYSTAB_SIGNATURE);
    put32(&mut v, 8, SYSTAB_REVISION);
    put32(&mut v, 12, SYSTAB_HEADER_SIZE);
    put64(&mut v, SYSTAB_FW_VENDOR, EFI_PAGE + EFI_VENDOR);
    put32(&mut v, SYSTAB_NR_TABLES, 1);
    put64(&mut v, SYSTAB_TABLES, EFI_PAGE + EFI_CONFIG_TABLE);

    let at = EFI_CONFIG_TABLE as usize;
    v[at..at + 16].copy_from_slice(&UNACCEPTED_GUID);
    put64(&mut v, at + 16, UNACCEPTED_TABLE);

    for (n, c) in "tinfoil".encode_utf16().enumerate() {
        v[EFI_VENDOR as usize + 2 * n..][..2].copy_from_slice(&c.to_le_bytes());
    }

    // Linux reserves the map's own bytes, and this page is reserved in E820
    // too; the shim appends the RAM after this descriptor.
    let at = EFI_MEMMAP as usize;
    put32(&mut v, at, EFI_LOADER_DATA);
    put64(&mut v, at + 8, EFI_PAGE);
    put64(&mut v, at + 24, 1);
    put64(&mut v, at + 32, EFI_MEMORY_WB);

    let at = (UNACCEPTED_TABLE - EFI_PAGE) as usize;
    put32(&mut v, at, UNACCEPTED_VERSION);
    put32(&mut v, at + 4, UNACCEPTED_UNIT as u32);
    v
}

/// boot_params.efi_info, pointing Linux at that page. The map's size is the
/// measured descriptor's until a shim appends the RAM to it.
pub fn claim_boot(zero: &mut [u8]) {
    let at = BP_EFI_INFO as usize;
    put32(zero, at, EL64);
    put32(zero, at + 4, EFI_PAGE as u32);
    put32(zero, at + 8, EFI_MEMDESC_SIZE as u32);
    put32(zero, at + 12, EFI_MEMDESC_VERSION);
    put32(zero, at + 16, (EFI_PAGE + EFI_MEMMAP) as u32);
    put32(zero, (BP_EFI_MEMMAP_SIZE) as usize, EFI_MEMDESC_SIZE as u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(v: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(v[at..at + 8].try_into().unwrap())
    }

    fn half(v: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
    }

    /// What arch/x86/boot/compressed/efi.c and drivers/firmware/efi/efi.c
    /// follow, from the zero page to the table, at the spec's own numbers.
    #[test]
    fn linux_finds_the_unaccepted_table_where_it_looks() {
        let mut zero = vec![0u8; PAGE as usize];
        claim_boot(&mut zero);
        assert_eq!(&zero[0x1c0..0x1c4], b"EL64");
        assert_eq!(half(&zero, 0x1c4) as u64, EFI_PAGE);
        assert_eq!(half(&zero, 0x1c8), 48, "efi_memdesc_size");
        assert_eq!(half(&zero, 0x1cc), 1, "efi_memdesc_version");
        assert_eq!(half(&zero, 0x1d0) as u64, EFI_PAGE + EFI_MEMMAP);
        assert_eq!(half(&zero, 0x1d4), 48, "efi_memmap_size: one descriptor");
        // efi_systab_hi and efi_memmap_hi stay zero: everything is below 4 GiB.
        assert_eq!(&zero[0x1d8..0x1e0], &[0u8; 8]);
        let p = page();
        assert_eq!(
            word(&p, 0),
            0x5453595320494249,
            "EFI_SYSTEM_TABLE_SIGNATURE"
        );
        assert_eq!(half(&p, 104), 1);
        let tables = word(&p, 112) - EFI_PAGE;
        assert_eq!(
            p[tables as usize..tables as usize + 16],
            [
                0x3c, 0xde, 0xd1, 0xd5, 0x5c, 0x10, 0xf9, 0x44, 0x9e, 0xa9, 0xbc, 0xef, 0x98, 0x12,
                0x00, 0x31
            ]
        );
        let table = word(&p, tables as usize + 16);
        assert_eq!(table, UNACCEPTED_TABLE);
        let at = (table - EFI_PAGE) as usize;
        assert_eq!(half(&p, at), 1);
        assert_eq!(half(&p, at + 4), 0x20_0000);
        // phys_base zero, and the size the shim writes left zero here.
        assert_eq!(word(&p, at + 8), 0);
        assert_eq!(word(&p, at + 16), 0);
        // ...and the bitmap is the page after: the table's flexible array.
        assert_eq!(table + 24, EFI_PAGE + PAGE);
        // No boot or runtime services for anything to call.
        assert_eq!(word(&p, 88), 0);
        assert_eq!(word(&p, 96), 0);
        // The measured descriptor: EfiLoaderData, this one page, write-back.
        let md = EFI_MEMMAP as usize;
        assert_eq!(half(&p, md), 2);
        assert_eq!(word(&p, md + 8), EFI_PAGE);
        assert_eq!(word(&p, md + 24), 1);
        assert_eq!(word(&p, md + 32), 8);
        // ...and the room after it the shim appends to is still zero.
        assert!(p[md + 48..(UNACCEPTED_TABLE - EFI_PAGE) as usize]
            .iter()
            .all(|b| *b == 0));
    }
}

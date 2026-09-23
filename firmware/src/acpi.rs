use crate::{
    boot::{put32, put64},
    layout::*,
};

const OEM_ID: &[u8; 6] = b"TINFOI";
const OEM_TABLE_ID: &[u8; 8] = b"TINFOIL ";
const CREATOR_ID: &[u8; 4] = b"TFNL";
const TABLE_HEADER_LEN: usize = 36;

const RSDP_CHECKSUM: usize = 8;
const RSDP_OEM_ID: usize = 9;
const RSDP_REVISION: usize = 15;
const RSDP_LENGTH: usize = 20;
const RSDP_XSDT: usize = 24;
const RSDP_EXT_CHECKSUM: usize = 32;
// The first checksum covers the ACPI 1.0 half of the structure only.
const RSDP_V1_LEN: usize = 20;

const FADT_DSDT: usize = 40;
const FADT_FLAGS: usize = 112;
const FADT_MINOR_VERSION: usize = 131;
const FADT_X_DSDT: usize = 140;
const FADT_WBINVD: u32 = 1;
const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;

const MADT_LAPIC_ADDR: usize = 36;
const MADT_FLAGS: usize = 40;
const MADT_PCAT_COMPAT: u32 = 1;
const MADT_LOCAL_APIC: u8 = 0;
const MADT_WAKEUP: u8 = 16;
const LAPIC_ENABLED: u32 = 1;
const LOCAL_APIC_ADDR: u32 = 0xfee0_0000;

/// One measured page: the RSDP at ACPI_BASE, the rest at the offsets layout.rs checks.
pub fn build(cpus: u32, wakeup: bool) -> Vec<u8> {
    let xsdt = ACPI_BASE + ACPI_XSDT;
    let fadt = ACPI_BASE + ACPI_FADT;
    let dsdt = ACPI_BASE + ACPI_DSDT;
    let madt = ACPI_BASE + ACPI_MADT;
    let mut bytes = vec![0u8; PAGE as usize];

    bytes[0..8].copy_from_slice(b"RSD PTR ");
    bytes[RSDP_OEM_ID..RSDP_OEM_ID + 6].copy_from_slice(OEM_ID);
    bytes[RSDP_REVISION] = 2;
    put32(&mut bytes, RSDP_LENGTH, RSDP_LEN as u32);
    put64(&mut bytes, RSDP_XSDT, xsdt);
    bytes[RSDP_CHECKSUM] = checksum(&bytes[0..RSDP_V1_LEN]);
    bytes[RSDP_EXT_CHECKSUM] = checksum(&bytes[0..RSDP_LEN as usize]);

    let xo = (xsdt - ACPI_BASE) as usize;
    header(&mut bytes[xo..], b"XSDT", XSDT_LEN as u32, 1);
    put64(&mut bytes, xo + TABLE_HEADER_LEN, fadt);
    put64(&mut bytes, xo + TABLE_HEADER_LEN + 8, madt);
    finish(&mut bytes[xo..xo + XSDT_LEN as usize]);

    // Linux disables ACPI when acpi_load_tables() finds no DSDT to load.
    let fo = (fadt - ACPI_BASE) as usize;
    header(&mut bytes[fo..], b"FACP", FADT_LEN as u32, 6);
    put32(&mut bytes, fo + FADT_DSDT, dsdt as u32);
    put32(
        &mut bytes,
        fo + FADT_FLAGS,
        FADT_HW_REDUCED_ACPI | FADT_WBINVD,
    );
    bytes[fo + FADT_MINOR_VERSION] = 5;
    put64(&mut bytes, fo + FADT_X_DSDT, dsdt);
    finish(&mut bytes[fo..fo + FADT_LEN as usize]);

    let do_ = (dsdt - ACPI_BASE) as usize;
    header(&mut bytes[do_..], b"DSDT", DSDT_LEN as u32, 2);
    finish(&mut bytes[do_..do_ + DSDT_LEN as usize]);

    let mo = (madt - ACPI_BASE) as usize;
    let madt_len = madt_len(cpus, wakeup) as usize;
    header(&mut bytes[mo..], b"APIC", madt_len as u32, 6);
    put32(&mut bytes, mo + MADT_LAPIC_ADDR, LOCAL_APIC_ADDR);
    put32(&mut bytes, mo + MADT_FLAGS, MADT_PCAT_COMPAT);
    let mut at = mo + MADT_HEADER_LEN as usize;
    for id in 0..cpus {
        bytes[at] = MADT_LOCAL_APIC;
        bytes[at + 1] = MADT_LAPIC_LEN as u8;
        bytes[at + 2] = id as u8;
        bytes[at + 3] = id as u8;
        put32(&mut bytes, at + 4, LAPIC_ENABLED);
        at += MADT_LAPIC_LEN as usize;
    }
    if wakeup {
        bytes[at] = MADT_WAKEUP;
        bytes[at + 1] = MADT_WAKEUP_LEN as u8;
        put64(&mut bytes, at + 8, MAILBOX);
    }
    finish(&mut bytes[mo..mo + madt_len]);
    bytes
}

fn madt_len(cpus: u32, wakeup: bool) -> u64 {
    MADT_HEADER_LEN + cpus as u64 * MADT_LAPIC_LEN + if wakeup { MADT_WAKEUP_LEN } else { 0 }
}

fn header(dst: &mut [u8], signature: &[u8; 4], len: u32, revision: u8) {
    dst[0..4].copy_from_slice(signature);
    dst[4..8].copy_from_slice(&len.to_le_bytes());
    dst[8] = revision;
    dst[10..16].copy_from_slice(OEM_ID);
    dst[16..24].copy_from_slice(OEM_TABLE_ID);
    dst[24..28].copy_from_slice(&1u32.to_le_bytes());
    dst[28..32].copy_from_slice(CREATOR_ID);
    dst[32..36].copy_from_slice(&1u32.to_le_bytes());
}
fn checksum(v: &[u8]) -> u8 {
    (0u8).wrapping_sub(v.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
}
fn finish(v: &mut [u8]) {
    v[9] = 0;
    v[9] = checksum(v);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tables_have_valid_checksums_and_wakeup() {
        let a = build(DEFAULT_VCPUS, true);
        assert_eq!(
            a[0..RSDP_LEN as usize]
                .iter()
                .fold(0u8, |x, y| x.wrapping_add(*y)),
            0
        );
        let mo = ACPI_MADT as usize;
        let len = u32::from_le_bytes(a[mo + 4..mo + 8].try_into().unwrap()) as usize;
        assert_eq!(
            a[mo..mo + len].iter().fold(0u8, |x, y| x.wrapping_add(*y)),
            0
        );
        assert_eq!(a[mo + madt_len(DEFAULT_VCPUS, false) as usize], MADT_WAKEUP);
    }
    #[test]
    fn snp_madt_scales_with_the_processor_count_and_has_no_wakeup() {
        // SNP launches every processor from its own measured VMSA, so the MADT
        // advertises them all but offers no wakeup structure to start them.
        for cpus in [1, 2, 16] {
            let a = build(cpus, false);
            let at = ACPI_MADT as usize + 4;
            let len = u32::from_le_bytes(a[at..at + 4].try_into().unwrap()) as u64;
            assert_eq!(len, madt_len(cpus, false));
            assert_eq!(len, MADT_HEADER_LEN + cpus as u64 * MADT_LAPIC_LEN);
        }
    }
    #[test]
    fn the_largest_allowed_madt_still_fits_its_measured_page() {
        let a = build(MAX_VCPUS, true);
        let at = ACPI_MADT as usize;
        let len = u32::from_le_bytes(a[at + 4..at + 8].try_into().unwrap()) as usize;
        assert!(at + len <= PAGE as usize);
    }
}

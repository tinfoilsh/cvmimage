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

/// One measured page: the RSDP at ACPI_BASE, the rest at the offsets layout.rs
/// checks. The page stops at ACPI_MADT, which a shim fills from the processor
/// count the loader passes it, so no processor count enters the measurement.
pub fn build() -> Vec<u8> {
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

    bytes
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
    use crate::{kernel::RESET_SHIM, vmsa::SNP_SHIM};

    const MADT_LAPIC_ADDR: usize = 36;
    const MADT_FLAGS: usize = 40;
    const MADT_PCAT_COMPAT: u32 = 1;
    const LOCAL_APIC_ADDR: u32 = 0xfee0_0000;

    /// The fixed part of the MADT, which each shim carries in its measured page.
    fn madt_template() -> Vec<u8> {
        let mut v = vec![0u8; MADT_HEADER_LEN as usize];
        header(&mut v, b"APIC", 0, 6);
        put32(&mut v, MADT_LAPIC_ADDR, LOCAL_APIC_ADDR);
        put32(&mut v, MADT_FLAGS, MADT_PCAT_COMPAT);
        v
    }

    /// The table a shim must produce from that template: one entry per processor,
    /// and on TDX the wakeup structure Linux starts them through.
    fn madt(cpus: u32, wakeup: bool) -> Vec<u8> {
        let mut v = madt_template();
        for id in 0..cpus {
            v.extend_from_slice(&[
                MADT_LOCAL_APIC as u8,
                MADT_LAPIC_LEN as u8,
                id as u8,
                id as u8,
            ]);
            v.extend_from_slice(&(LAPIC_ENABLED as u32).to_le_bytes());
        }
        if wakeup {
            v.resize(v.len() + MADT_WAKEUP_LEN as usize, 0);
            let at = v.len() - MADT_WAKEUP_LEN as usize;
            v[at] = MADT_WAKEUP as u8;
            v[at + 1] = MADT_WAKEUP_LEN as u8;
            put64(&mut v, at + 8, MAILBOX);
        }
        let len = v.len() as u32;
        put32(&mut v, 4, len);
        finish(&mut v);
        v
    }

    fn sums_to_zero(v: &[u8]) -> bool {
        v.iter().fold(0u8, |x, y| x.wrapping_add(*y)) == 0
    }

    /// The algorithm madt.inc assembles, over the template the shim carries.
    fn shim_madt(shim: &[u8], cpus: u32, wakeup: bool) -> Vec<u8> {
        let at = SHIM_MADT as usize;
        let mut v = shim[at..at + MADT_HEADER_LEN as usize].to_vec();
        for id in 0..cpus {
            let entry = ((id & 0xff) * 0x0101_0000)
                | ((MADT_LAPIC_LEN as u32) << 8)
                | MADT_LOCAL_APIC as u32;
            v.extend_from_slice(&entry.to_le_bytes());
            v.extend_from_slice(&(LAPIC_ENABLED as u32).to_le_bytes());
        }
        if wakeup {
            let at = v.len();
            v.resize(at + MADT_WAKEUP_LEN as usize, 0);
            v[at] = MADT_WAKEUP as u8;
            v[at + 1] = MADT_WAKEUP_LEN as u8;
            put64(&mut v, at + 8, MAILBOX);
        }
        let len = v.len() as u32;
        put32(&mut v, 4, len);
        v[9] = 0;
        v[9] = checksum(&v);
        v
    }

    #[test]
    fn tables_have_valid_checksums() {
        let a = build();
        assert!(sums_to_zero(&a[0..RSDP_LEN as usize]));
        for (at, len) in [
            (ACPI_XSDT, XSDT_LEN),
            (ACPI_FADT, FADT_LEN),
            (ACPI_DSDT, DSDT_LEN),
        ] {
            let (at, len) = (at as usize, len as usize);
            assert!(sums_to_zero(&a[at..at + len]), "{at:#x} does not check out");
        }
    }

    /// The measured page ends where the shim's table begins: nothing below it
    /// depends on the processor count, and the XSDT checksum covers none of it.
    #[test]
    fn the_measured_page_stops_at_the_madt() {
        let a = build();
        assert!(a[ACPI_MADT as usize..].iter().all(|b| *b == 0));
        let at = (ACPI_XSDT + TABLE_HEADER_LEN as u64 + 8) as usize;
        assert_eq!(
            u64::from_le_bytes(a[at..at + 8].try_into().unwrap()),
            ACPI_BASE + ACPI_MADT
        );
    }

    /// The reference table, which the shims are held to below.
    #[test]
    fn the_madt_scales_with_the_processor_count() {
        for cpus in [1, 2, 16, MAX_VCPUS] {
            for wakeup in [false, true] {
                let m = madt(cpus, wakeup);
                let wake = if wakeup { MADT_WAKEUP_LEN } else { 0 };
                let len = MADT_HEADER_LEN + cpus as u64 * MADT_LAPIC_LEN + wake;
                assert_eq!(m.len() as u64, len);
                assert_eq!(u32::from_le_bytes(m[4..8].try_into().unwrap()) as u64, len);
                assert!(sums_to_zero(&m));
                // The largest table a shim will build still fits its page.
                assert!(ACPI_MADT + len <= PAGE);
                if wakeup {
                    let at = (len - MADT_WAKEUP_LEN) as usize;
                    assert_eq!(m[at], MADT_WAKEUP as u8);
                    assert_eq!(
                        u64::from_le_bytes(m[at + 8..at + 16].try_into().unwrap()),
                        MAILBOX
                    );
                }
            }
        }
    }

    /// Each shim carries the fixed half of the table in its own measured page,
    /// and writing the rest around it reproduces the table this file states.
    /// SNP launches every processor from its own measured save area, so only
    /// the TDX shim writes a wakeup structure.
    #[test]
    fn each_shim_builds_the_madt_this_file_specifies() {
        for (shim, wakeup) in [(RESET_SHIM, true), (SNP_SHIM, false)] {
            let at = SHIM_MADT as usize;
            assert_eq!(
                &shim[at..at + MADT_HEADER_LEN as usize],
                &madt_template()[..]
            );
            for cpus in [1, 2, 16, 255, MAX_VCPUS] {
                assert_eq!(shim_madt(shim, cpus, wakeup), madt(cpus, wakeup));
            }
        }
    }
}

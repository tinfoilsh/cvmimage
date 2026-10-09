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
const FADT_SCI: usize = 46;
const FADT_PM1A_EVENT: usize = 56;
const FADT_PM1A_CONTROL: usize = 64;
const FADT_PM_TIMER: usize = 76;
const FADT_PM1_EVENT_LEN: usize = 88;
const FADT_PM1_CONTROL_LEN: usize = 89;
const FADT_PM_TIMER_LEN: usize = 91;
const FADT_C2_LATENCY: usize = 96;
const FADT_C3_LATENCY: usize = 98;
const FADT_FLAGS: usize = 112;
const FADT_MINOR_VERSION: usize = 131;
const FADT_X_DSDT: usize = 140;
const FADT_WBINVD: u32 = 1;
const FADT_SLEEP_BUTTON: u32 = 1 << 5;
// Name (_S5, Package (4) { 0, 0, 0, 0 }): Q35's soft-off sleep type is zero.
const S5_AML: &[u8] = b"\x08_S5_\x12\x06\x04\0\0\0\0";
// Scope (_SB) { Device (PCI0) { Name (_HID, EisaId ("PNP0A03")) } }
// PCI resources come from the E820 map, not a second copy in _CRS.
const PCI_ROOT_AML: &[u8] = b"\x10\x16_SB_\x5b\x82\x0fPCI0\x08_HID\x0c\x41\xd0\x0a\x03";

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
    bytes[fo + FADT_SCI..fo + FADT_SCI + 2].copy_from_slice(&(ACPI_SCI_IRQ as u16).to_le_bytes());
    put32(&mut bytes, fo + FADT_PM1A_EVENT, Q35_PM_BASE as u32);
    put32(&mut bytes, fo + FADT_PM1A_CONTROL, Q35_PM_CONTROL as u32);
    put32(&mut bytes, fo + FADT_PM_TIMER, Q35_PM_TIMER as u32);
    bytes[fo + FADT_PM1_EVENT_LEN] = 4;
    bytes[fo + FADT_PM1_CONTROL_LEN] = 2;
    bytes[fo + FADT_PM_TIMER_LEN] = 4;
    bytes[fo + FADT_C2_LATENCY..fo + FADT_C2_LATENCY + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes[fo + FADT_C3_LATENCY..fo + FADT_C3_LATENCY + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    put32(&mut bytes, fo + FADT_FLAGS, FADT_SLEEP_BUTTON | FADT_WBINVD);
    bytes[fo + FADT_MINOR_VERSION] = 5;
    put64(&mut bytes, fo + FADT_X_DSDT, dsdt);
    finish(&mut bytes[fo..fo + FADT_LEN as usize]);

    let do_ = (dsdt - ACPI_BASE) as usize;
    header(&mut bytes[do_..], b"DSDT", DSDT_LEN as u32, 2);
    let aml = [S5_AML, PCI_ROOT_AML].concat();
    bytes[do_ + TABLE_HEADER_LEN..do_ + DSDT_LEN as usize].copy_from_slice(&aml);
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
        v.extend_from_slice(&[MADT_IOAPIC as u8, MADT_IOAPIC_LEN as u8, 0, 0]);
        v.extend_from_slice(&(IOAPIC_ADDRESS as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&[MADT_OVERRIDE as u8, MADT_OVERRIDE_LEN as u8, 0, 0]);
        v.extend_from_slice(&(Q35_PIT_GSI as u32).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&[
            MADT_OVERRIDE as u8,
            MADT_OVERRIDE_LEN as u8,
            0,
            ACPI_SCI_IRQ as u8,
        ]);
        v.extend_from_slice(&(ACPI_SCI_IRQ as u32).to_le_bytes());
        v.extend_from_slice(&(MADT_SCI_FLAGS as u16).to_le_bytes());
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

    #[test]
    fn both_shims_initialize_the_power_registers_the_fadt_describes() {
        let a = build();
        let f = ACPI_FADT as usize;
        let word = |at| u16::from_le_bytes(a[f + at..f + at + 2].try_into().unwrap());
        let dword = |at| u32::from_le_bytes(a[f + at..f + at + 4].try_into().unwrap());
        assert_eq!(word(FADT_SCI) as u64, ACPI_SCI_IRQ);
        assert_eq!(dword(FADT_FLAGS) & (1 << 20 | 1 << 4), 0);
        let base = dword(FADT_PM1A_EVENT) as u64;
        assert_eq!(dword(FADT_PM1A_CONTROL) as u64, base + 4);
        assert_eq!(dword(FADT_PM_TIMER) as u64, base + 8);
        assert_eq!(a[f + FADT_PM1_EVENT_LEN], 4);
        assert_eq!(a[f + FADT_PM1_CONTROL_LEN], 2);
        assert_eq!(a[f + FADT_PM_TIMER_LEN], 4);

        let writes = [
            (4, PCI_CONFIG_ADDRESS, Q35_LPC_PMBASE),
            (4, PCI_CONFIG_DATA, base | Q35_PM_IO_ENABLE),
            (4, PCI_CONFIG_ADDRESS, Q35_LPC_ACPI_CTRL),
            (4, PCI_CONFIG_DATA, Q35_ACPI_ENABLE),
            (2, base + 4, ACPI_SCI_ENABLE),
        ];
        let shim = crate::shim::shim();
        for tdx in [false, true] {
            let (success, requests) = shim.power(tdx, 0, false);
            assert!(success);
            assert_eq!(requests.len(), writes.len());
            for (request, (size, port, value)) in requests.iter().zip(writes) {
                let expected = if tdx {
                    [0, 0xfc00, 0, 30, size, 1, port, value]
                } else {
                    [
                        SVM_EXIT_IOIO,
                        port << 16 | size << 4 | IOIO_ADDR_64,
                        0,
                        value,
                        1 << 63,
                        7 << 50,
                        GHCB_PROTOCOL,
                        0,
                    ]
                };
                assert_eq!(*request, expected, "TDX={tdx}");
            }
        }
    }

    #[test]
    fn a_refused_power_write_stops_boot_without_retrying() {
        let shim = crate::shim::shim();
        for (tdx, module_failure) in [(false, false), (true, false), (true, true)] {
            let (_, all) = shim.power(tdx, 0, false);
            for fail_at in 1..=all.len() {
                let (success, requests) = shim.power(tdx, fail_at as u64, module_failure);
                assert!(
                    !success,
                    "TDX={tdx}, module={module_failure}, write={fail_at}"
                );
                assert_eq!(requests, all[..fail_at]);
            }
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
                let len = MADT_TEMPLATE_LEN + cpus as u64 * MADT_LAPIC_LEN + wake;
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
    /// and the assembly that writes the rest around it -- run here, not
    /// re-implemented -- reproduces the table this file states. SNP launches
    /// every processor from its own measured save area, so only the TDX shim
    /// writes a wakeup structure.
    #[test]
    fn each_shim_builds_the_madt_this_file_specifies() {
        let shim = crate::shim::shim();
        let at = SHIM_MADT as usize;
        for page in [RESET_SHIM, SNP_SHIM] {
            assert_eq!(
                &page[at..at + MADT_TEMPLATE_LEN as usize],
                &madt_template()[..]
            );
        }
        // The assembly copies its own page's header, so the harness carries the
        // same one, and the shims above are held to it.
        assert_eq!(shim.madt_template(), &madt_template()[..]);
        for cpus in [1, 2, 16, 64, 254, MAX_VCPUS] {
            for wakeup in [false, true] {
                shim.loader_vcpus(cpus);
                assert_eq!(
                    shim.madt(wakeup),
                    Some(madt(cpus, wakeup)),
                    "the table the shim built for {cpus} processors"
                );
            }
        }
    }

    /// The count is unmeasured and the host writes it, so a shim that reads one
    /// it cannot describe terminates rather than clamping or aliasing.
    #[test]
    fn a_processor_count_outside_the_table_is_refused() {
        let shim = crate::shim::shim();
        for cpus in [0, MAX_VCPUS + 1, 256, 344, u32::MAX] {
            shim.loader_vcpus(cpus);
            for wakeup in [false, true] {
                assert_eq!(shim.madt(wakeup), None, "{cpus} processors was accepted");
            }
        }
    }
}

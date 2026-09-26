//! The processor state a SEV-SNP guest launches with. One save area per
//! processor is measured, so these values are attested, not a build detail.

use crate::boot::{put32, put64};
use crate::layout::*;
use igvm::snp_defs::{SevFeatures, SevSelector, SevVmsa};
use zerocopy::{AsBytes, FromZeroes};

// The VMSA reset state, pinned here because the launch digest covers all of it.
const VMSA_CR0: u64 = 0x31;
const VMSA_CR4: u64 = 0x60;
const VMSA_EFER: u64 = 0x1000;
const VMSA_RFLAGS: u64 = 2;
const VMSA_XCR0: u64 = 1;
const VMSA_PAT: u64 = 0x0007_0406_0007_0406;
const VMSA_DR6: u64 = 0xffff_0ff0;
const VMSA_DR7: u64 = 0x400;
const VMSA_MXCSR: u32 = 0x1f80;
const VMSA_X87_FCW: u16 = 0x037f;
const SEG_CODE32_ATTR: u16 = 0x0c9b;
const SEG_DATA_ATTR: u16 = 0x0c93;
const SEG_LIMIT: u32 = 0xffff_ffff;

/// The SEV-SNP reset shim, assembled by build.rs.
pub(crate) const SNP_SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/snp_reset.bin"));
const _: () = assert!(SNP_SHIM.len() == SHIM_SIZE as usize);

pub fn bsp_vmsa() -> Box<SevVmsa> {
    let mut v = SevVmsa::new_box_zeroed();
    let data = SevSelector {
        selector: BOOT_DS as u16,
        attrib: SEG_DATA_ATTR,
        limit: SEG_LIMIT,
        base: 0,
    };
    v.es = data;
    v.ss = data;
    v.ds = data;
    v.fs = data;
    v.gs = data;
    // The VMSA enters 32-bit protected mode; the shim far-returns to BOOT_CS.
    v.cs = SevSelector {
        selector: BOOT_CS32 as u16,
        attrib: SEG_CODE32_ATTR,
        limit: SEG_LIMIT,
        base: 0,
    };
    v.gdtr = SevSelector {
        selector: 0,
        attrib: 0,
        limit: GDT_LIMIT as u32,
        base: BSP_STACK,
    };
    v.idtr = SevSelector {
        selector: 0,
        attrib: 0,
        limit: 0,
        base: 0,
    };
    v.ldtr = v.idtr;
    v.tr = v.idtr;
    // The KVM reset state the shim starts from, paging and long mode left to it.
    v.efer = VMSA_EFER;
    v.cr4 = VMSA_CR4;
    v.cr3 = 0;
    v.cr0 = VMSA_CR0;
    v.dr6 = VMSA_DR6;
    v.dr7 = VMSA_DR7;
    v.rflags = VMSA_RFLAGS;
    v.rip = SHIM_BASE;
    v.rsp = BSP_STACK_TOP;
    v.rsi = ZERO_PAGE;
    v.pat = VMSA_PAT;
    v.xcr0 = VMSA_XCR0;
    // RDX stays zero, so no CPU family, model or stepping reaches the measurement.
    v.mxcsr = VMSA_MXCSR;
    v.x87_fcw = VMSA_X87_FCW;
    v.sev_features = SevFeatures::new().with_snp(true);
    v
}


pub fn validate_vmsa(v: &SevVmsa, rip: u64, rsp: u64, rsi: u64) -> Result<(), String> {
    let data = |s: &SevSelector, sel: u64, attrib: u16| {
        s.selector == sel as u16 && s.attrib == attrib && s.limit == SEG_LIMIT && s.base == 0
    };
    let pinned = v.cr0 == VMSA_CR0
        && v.cr3 == 0
        && v.cr4 == VMSA_CR4
        && v.efer == VMSA_EFER
        && v.rdx == 0
        && v.rip == rip
        && v.rsp == rsp
        && v.rsi == rsi
        && v.rflags == VMSA_RFLAGS
        && v.vmpl == 0
        && v.dr6 == VMSA_DR6
        && v.dr7 == VMSA_DR7
        && v.pat == VMSA_PAT
        && v.xcr0 == VMSA_XCR0
        && v.mxcsr == VMSA_MXCSR
        && v.x87_fcw == VMSA_X87_FCW
        && v.gdtr.base == BSP_STACK
        && v.gdtr.limit == GDT_LIMIT as u32
        && v.idtr.limit == 0
        && data(&v.cs, BOOT_CS32, SEG_CODE32_ATTR)
        && data(&v.ds, BOOT_DS, SEG_DATA_ATTR)
        && data(&v.ss, BOOT_DS, SEG_DATA_ATTR)
        && v.sev_features.into_bits() == SNP_SEV_FEATURES;
    if !pinned {
        return Err("SNP VMSA invariant failed".into());
    }
    Ok(())
}

pub fn vmsa_page(vmsa: &SevVmsa) -> Vec<u8> {
    let mut page = vec![0u8; PAGE as usize];
    page[..vmsa.as_bytes().len()].copy_from_slice(vmsa.as_bytes());
    page
}

const SETUP_DATA_TYPE: usize = 8;
const SETUP_DATA_LEN: usize = 12;
const SETUP_DATA_DATA: usize = 16;
const SETUP_DATA_HEADER: u32 = 16;
const SETUP_CC_BLOB: u32 = 7;
// The blob follows the record in the same page, clear of the address Linux reads.
const CC_BLOB_INFO: usize = 32;
const CC_MAGIC: &[u8; 4] = b"AMDE";
const CC_VERSION: usize = 4;
const CC_SECRETS_PHYS: usize = 8;
const CC_SECRETS_LEN: usize = 16;
const CC_CPUID_PHYS: usize = 24;
const CC_CPUID_LEN: usize = 32;

/// One measured page inside the E820 RAM map, found through a SETUP_CC_BLOB
/// setup_data record on the zero page.
pub(crate) fn cc_blob() -> Vec<u8> {
    let mut v = vec![0u8; PAGE as usize];
    put32(&mut v, SETUP_DATA_TYPE, SETUP_CC_BLOB);
    // The record claims the whole page, so Linux reserves all of it.
    put32(&mut v, SETUP_DATA_LEN, PAGE as u32 - SETUP_DATA_HEADER);
    put32(
        &mut v,
        SETUP_DATA_DATA,
        (SNP_CC_BLOB + CC_BLOB_INFO as u64) as u32,
    );
    v[CC_BLOB_INFO..CC_BLOB_INFO + 4].copy_from_slice(CC_MAGIC);
    v[CC_BLOB_INFO + CC_VERSION..CC_BLOB_INFO + CC_VERSION + 2]
        .copy_from_slice(&1u16.to_le_bytes());
    put64(&mut v, CC_BLOB_INFO + CC_SECRETS_PHYS, SNP_SECRETS);
    put32(&mut v, CC_BLOB_INFO + CC_SECRETS_LEN, PAGE as u32);
    put64(&mut v, CC_BLOB_INFO + CC_CPUID_PHYS, SNP_CPUID);
    put32(&mut v, CC_BLOB_INFO + CC_CPUID_LEN, PAGE as u32);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmsa_is_the_pinned_reset_state() {
        let v = bsp_vmsa();
        assert_eq!(vmsa_page(&v).len(), 4096);
        assert_eq!(v.cr0, 0x31);
        assert_eq!(v.cr3, 0);
        assert_eq!(v.cr4, 0x60);
        assert_eq!(v.efer, 0x1000);
        assert_eq!(v.rdx, 0);
        assert_eq!(v.cs.selector, BOOT_CS32 as u16);
        assert_eq!(v.cs.attrib, 0x0c9b);
        assert_eq!(v.mxcsr, 0x1f80);
        assert_eq!(v.x87_fcw, 0x037f);
        assert_eq!(v.rsi, ZERO_PAGE);
        assert!(validate_vmsa(&v, SHIM_BASE, BSP_STACK_TOP, ZERO_PAGE).is_ok());
        // Drift in the state QEMU supplies changes the measurement, so none goes unchecked.
        for break_it in [
            (|v: &mut SevVmsa| v.dr6 = 0) as fn(&mut SevVmsa),
            |v| v.dr7 = 0,
            |v| v.pat = 0,
            |v| v.xcr0 = 0,
            |v| v.mxcsr = 0,
            |v| v.x87_fcw = 0,
            |v| v.cr4 = 0,
            |v| v.efer = 0,
            |v| v.rsp = 0,
            |v| v.rflags = 0,
            |v| v.gdtr.base = 0,
            |v| v.idtr.limit = 1,
            |v| v.cs.attrib = 0,
            |v| v.ds.selector = 0,
        ] {
            let mut v = bsp_vmsa();
            break_it(&mut v);
            assert!(validate_vmsa(&v, SHIM_BASE, BSP_STACK_TOP, ZERO_PAGE).is_err());
        }
    }
    #[test]
    fn cc_blob_points_to_special_pages() {
        let c = cc_blob();
        let info = CC_BLOB_INFO;
        assert_eq!(u32::from_le_bytes(c[8..12].try_into().unwrap()), 7);
        assert_eq!(
            u32::from_le_bytes(c[12..16].try_into().unwrap()) + SETUP_DATA_HEADER,
            PAGE as u32
        );
        // ...and the chain ends here: `pcibios_device_add()` walks it long after boot.
        assert_eq!(u64::from_le_bytes(c[0..8].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(c[16..20].try_into().unwrap()) as u64,
            SNP_CC_BLOB + info as u64
        );
        assert_eq!(&c[info..info + 4], b"AMDE");
        assert_eq!(
            u64::from_le_bytes(c[info + 8..info + 16].try_into().unwrap()),
            SNP_SECRETS
        );
        assert_eq!(
            u64::from_le_bytes(c[info + 24..info + 32].try_into().unwrap()),
            SNP_CPUID
        );
    }
}

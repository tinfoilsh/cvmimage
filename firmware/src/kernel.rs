//! A bzImage and an initramfs as measured pages. The setup header is patched
//! as a loader would, because the patched bytes are what the digest covers.

use crate::boot::{self, put64, Fill, Placed};
use crate::io_error;
use crate::layout::*;
use std::{fs, path::Path};

/// The reset shim, assembled by build.rs.
pub(crate) const RESET_SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/reset.bin"));
const _: () = assert!(RESET_SHIM.len() == SHIM_SIZE as usize);

pub struct Prepared {
    pub info: boot::KernelInfo,
    pub setup: Vec<u8>,
    pub kernel: Vec<u8>,
    pub initramfs: Vec<u8>,
    pub command: Vec<u8>,
    pub entry: u64,
}

pub(crate) fn prepare(
    kernel_path: &Path,
    initramfs_path: &Path,
    params: &Params,
) -> Result<Prepared, String> {
    let kernel_file = fs::read(kernel_path).map_err(io_error("read kernel"))?;
    let initramfs = fs::read(initramfs_path).map_err(io_error("read initramfs"))?;
    let info = boot::parse_bzimage(&kernel_file)?;
    let kernel = kernel_file[info.setup_bytes..].to_vec();
    let kernel_end = align_up(KERNEL_BASE + kernel.len() as u64, PAGE);
    let initramfs_end = align_up(INITRAMFS_BASE + initramfs.len() as u64, PAGE);
    if kernel_end > INITRAMFS_BASE {
        return Err("protected kernel overlaps the fixed initramfs address".into());
    }
    if KERNEL_BASE + info.init_size as u64 > INITRAMFS_BASE {
        return Err("kernel init_size overlaps the fixed initramfs address".into());
    }
    if initramfs_end > params.memory {
        return Err("initramfs exceeds the memory the image describes".into());
    }
    // boot_params addresses the initramfs with a 32-bit field.
    if initramfs_end > u32::MAX as u64 {
        return Err("initramfs does not fit below 4 GiB".into());
    }
    if info.setup_bytes > KERNEL_SETUP_AREA_SIZE as usize {
        return Err("bzImage setup area exceeds its fixed measured reservation".into());
    }
    // cmdline_size is the kernel's own limit on the command line this image measures.
    if params.cmdline.len() as u32 + 1 > info.cmdline_max {
        return Err(format!(
            "command line is longer than the {} bytes this kernel accepts",
            info.cmdline_max
        ));
    }
    let mut setup = vec![0u8; KERNEL_SETUP_AREA_SIZE as usize];
    setup[..info.setup_bytes].copy_from_slice(&kernel_file[..info.setup_bytes]);
    let mut command = params.cmdline.as_bytes().to_vec();
    command.push(0);
    command.resize(PAGE as usize, 0);
    Ok(Prepared {
        info,
        setup,
        kernel,
        initramfs,
        command,
        entry: KERNEL_BASE + boot::ENTRY_64_OFFSET,
    })
}

/// The shim, with the entry point and zero-terminated accept ranges packed in.
pub(crate) fn shim(blob: &[u8], entry: u64, ranges: &[(u64, u64)]) -> Result<Vec<u8>, String> {
    let mut data = entry.to_le_bytes().to_vec();
    for (lo, hi) in ranges {
        data.extend_from_slice(&lo.to_le_bytes());
        data.extend_from_slice(&hi.to_le_bytes());
    }
    data.extend_from_slice(&[0u8; 16]);
    if data.len() > SHIM_DATA_SIZE as usize {
        return Err(format!(
            "shim data block needs {} of {SHIM_DATA_SIZE} bytes",
            data.len()
        ));
    }
    let (mut shim, at) = (blob.to_vec(), SHIM_DATA as usize);
    if shim[at..at + data.len()].iter().any(|b| *b != 0) {
        return Err("shim code overruns its data block".into());
    }
    shim[at..at + data.len()].copy_from_slice(&data);
    Ok(shim)
}

/// The measured bytes this crate authors, as opposed to the kernel and initramfs.
pub(crate) fn shim_owned(placed: &[Placed]) -> Result<usize, String> {
    let owned: usize = placed
        .iter()
        .filter(|p| p.base < KERNEL_SETUP_BASE || p.base == RESET_ALIAS)
        .filter(|p| !matches!(p.fill, Fill::Mmio(_)))
        .map(|p| p.span() as usize)
        .sum();
    if owned > SHIM_LIMIT {
        return Err(format!(
            "shim-owned measured pages exceed {SHIM_LIMIT} bytes: {owned}"
        ));
    }
    Ok(owned)
}

/// The 4-level map covering [0, MAP_LIMIT); `c_bit` is 0 on TDX and the C-bit on SNP.
pub(crate) fn identity_map(c_bit: u64, shared_alias: bool) -> Vec<u8> {
    let c = if c_bit == 0 { 0 } else { 1u64 << c_bit };
    let pages = if shared_alias { 3 } else { 2 };
    let mut v = vec![0u8; pages * PAGE as usize];
    put64(&mut v, 0, (PAGE_TABLES + PAGE) | c | 3);
    for gib in 0..MAP_LIMIT / GIB {
        put64(&mut v, (PAGE + gib * 8) as usize, (gib * GIB) | c | 0x83);
    }
    if shared_alias {
        // PML4[1] -> a second PDPT whose first entry is physical GiB 0, unencrypted.
        put64(&mut v, 8, (PAGE_TABLES + 2 * PAGE) | c | 3);
        put64(&mut v, (2 * PAGE) as usize, 0x83);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::RAM;

    fn pdpte(map: &[u8], gpa: u64) -> u64 {
        let at = (PAGE + gpa / GIB * 8) as usize;
        u64::from_le_bytes(map[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn identity_map_reaches_the_bound_memory_is_held_to() {
        let p = identity_map(0, false);
        // PML4[0] points at the PDPT that follows it, whose entries are 1-GiB pages.
        assert_eq!(
            u64::from_le_bytes(p[..8].try_into().unwrap()),
            (PAGE_TABLES + PAGE) | 3
        );
        assert_eq!(pdpte(&p, 0), 0x83);
        assert_eq!(pdpte(&p, MAP_LIMIT - GIB), (MAP_LIMIT - GIB) | 0x83);
        assert_eq!(pdpte(&p, RESET_ALIAS) & 1, 1);
        let e = identity_map(DEFAULT_CBIT as u64, false);
        assert_eq!(p.len(), e.len());
        for at in (0..p.len()).step_by(8) {
            let (plain, enc) = (
                u64::from_le_bytes(p[at..at + 8].try_into().unwrap()),
                u64::from_le_bytes(e[at..at + 8].try_into().unwrap()),
            );
            assert_eq!(
                enc,
                if plain == 0 {
                    0
                } else {
                    plain | 1 << DEFAULT_CBIT
                }
            );
        }
    }
    /// On SNP, PML4[1] reaches physical GiB 0 again with the C-bit clear, and nothing else.
    #[test]
    fn the_shared_alias_maps_gib_zero_unencrypted() {
        let m = identity_map(DEFAULT_CBIT as u64, true);
        assert_eq!(m.len(), 3 * PAGE as usize);
        let pml4_1 = u64::from_le_bytes(m[8..16].try_into().unwrap());
        assert_eq!(pml4_1, (PAGE_TABLES + 2 * PAGE) | 1 << DEFAULT_CBIT | 3);
        let alias = &m[2 * PAGE as usize..];
        assert_eq!(u64::from_le_bytes(alias[..8].try_into().unwrap()), 0x83);
        assert!(alias[8..].iter().all(|b| *b == 0));
        assert_eq!(SHARED_ALIAS, 512 * GIB);
    }
    /// The SNP shim PVALIDATEs and zeroes through the map, so every range it walks is mapped.
    #[test]
    fn every_range_the_shim_is_told_to_touch_is_mapped() {
        for ram in [DEFAULT_RAM, 16 * GIB, MAX_RAM] {
            let params = Params::snp(ram, DEFAULT_VCPUS, DEFAULT_CBIT, "").unwrap();
            let map = identity_map(params.cbit as u64, true);
            let placed = vec![Placed::measured(
                KERNEL_BASE,
                "",
                RAM,
                vec![0u8; PAGE as usize],
            )];
            for (_, hi) in boot::accept_ranges(&placed, params.memory) {
                assert_eq!(pdpte(&map, hi - PAGE) & 1, 1, "{hi:#x} is unmapped");
            }
        }
        assert!(Params::snp(MAX_RAM + PAGE, DEFAULT_VCPUS, DEFAULT_CBIT, "").is_err());
    }
}

//! A bzImage and an initramfs as measured pages. The setup header is patched
//! as a loader would, because the patched bytes are what the digest covers.

use crate::boot::{self, put64, Fill, Placed};
use crate::io_error;
use crate::layout::*;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// The reset shim, assembled by build.rs.
pub(crate) const RESET_SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/reset.bin"));
const _: () = assert!(RESET_SHIM.len() == SHIM_SIZE as usize);

pub struct Prepared {
    pub info: boot::KernelInfo,
    pub setup: Vec<u8>,
    pub kernel: Vec<u8>,
    /// The SHA-256 of the whole bzImage, which is what an SNP loader serves.
    pub file_digest: [u8; 32],
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
    // boot_params addresses the initramfs with a 32-bit field, so its last
    // byte must be below 4 GiB; an exclusive end of exactly 4 GiB is fine.
    if initramfs_end > FOUR_GIB {
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
        file_digest: Sha256::digest(&kernel_file).into(),
        initramfs,
        command,
        entry: KERNEL_BASE + boot::ENTRY_64_OFFSET,
    })
}

/// The fw_cfg files the SNP shim fetches, as `-fw_cfg name=...,file=...` names
/// them and fetch.inc spells them.
pub const FWCFG_KERNEL: &str = "opt/tinfoil/kernel";
pub const FWCFG_INITRD: &str = "opt/tinfoil/initrd";
const _: () = assert!(FWCFG_KERNEL.len() + 1 == FETCH_NAME_LEN as usize);
const _: () = assert!(FWCFG_INITRD.len() + 1 == FETCH_NAME_LEN as usize);

/// One file the SNP shim fetches rather than has measured: where its bytes go,
/// how many of the fw_cfg file's leading bytes are not among them, and the
/// SHA-256 the shim holds those bytes to before anything runs them.
pub struct Fetch {
    pub dest: u64,
    pub skip: u64,
    pub size: u64,
    pub digest: [u8; 32],
}

impl Fetch {
    pub fn of(dest: u64, skip: u64, bytes: &[u8]) -> Fetch {
        Fetch {
            dest,
            skip,
            size: bytes.len() as u64,
            digest: Sha256::digest(bytes).into(),
        }
    }
}

// FIPS 180-4, 5.3.3 and 4.2.2: what sha256.inc starts from and folds in.
const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The shim, with the entry point, the least memory this image can run in and
/// the zero-terminated spans it placed packed in. The E820 map and the ranges
/// to accept both follow from those spans and the memory the loader reports,
/// so neither the guest's RAM nor anything derived from it is measured here.
/// An SNP shim also carries the files it fetches, the kernel's then the
/// initramfs's, and the SHA-256 constants it checks them with; a TDX shim
/// fetches nothing and leaves that end of the block zero.
pub fn data_block(
    entry: u64,
    spans: &[boot::Region],
    fetch: &[Fetch],
    lazy: u64,
) -> Result<Vec<u8>, String> {
    // Each span can cost the E820 map a gap entry and an entry of its own, and
    // the RAM above the last of them one more. What the loader's map adds to
    // that is not known until boot, so the shim counts the entries it writes
    // and terminates rather than overrunning boot_params.
    if 2 * spans.len() + 1 > E820_MAX as usize {
        return Err(format!(
            "{} placed spans can describe more than the {E820_MAX} E820 entries \
             boot_params holds",
            spans.len()
        ));
    }
    let mut data = entry.to_le_bytes().to_vec();
    data.extend_from_slice(&boot::min_memory(spans).to_le_bytes());
    for (lo, hi, kind) in spans {
        data.extend_from_slice(&lo.to_le_bytes());
        data.extend_from_slice(&hi.to_le_bytes());
        data.extend_from_slice(&kind.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
    }
    data.extend_from_slice(&[0u8; SPAN_LEN as usize]);
    if data.len() > SHIM_DATA_LAZY as usize {
        return Err(format!(
            "shim data block needs {} of the {SHIM_DATA_LAZY} bytes its spans have",
            data.len()
        ));
    }
    // accept_lazy marks every whole unit past the bound, so one that left the
    // bitmap or the decompressor to Linux would mark memory nothing accepts.
    if !lazy.is_multiple_of(UNACCEPTED_UNIT) || lazy < UNACCEPTED_BITMAP + UNACCEPTED_BITMAP_SIZE {
        return Err(format!(
            "{lazy:#x} is not a lazy bound past the unaccepted bitmap"
        ));
    }
    data.resize(SHIM_DATA_SIZE as usize, 0);
    put64(&mut data, SHIM_DATA_LAZY as usize, lazy);
    match fetch {
        [] => {}
        [kernel, initramfs] => {
            data.resize(SHIM_DATA_SIZE as usize, 0);
            let words = SHA256_H.iter().chain(SHA256_K.iter());
            for (n, word) in words.enumerate() {
                let at = SHIM_DATA_SHA_H as usize + 4 * n;
                data[at..at + 4].copy_from_slice(&word.to_le_bytes());
            }
            let named = [(kernel, FWCFG_KERNEL), (initramfs, FWCFG_INITRD)];
            for (n, (f, name)) in named.into_iter().enumerate() {
                let at = (SHIM_DATA_FETCH + n as u64 * FETCH_LEN) as usize;
                put64(&mut data, at + FETCH_DEST as usize, f.dest);
                put64(&mut data, at + FETCH_SKIP as usize, f.skip);
                put64(&mut data, at + FETCH_SIZE as usize, f.size);
                data[at + FETCH_DIGEST as usize..][..32].copy_from_slice(&f.digest);
                data[at + FETCH_NAME as usize..][..name.len()].copy_from_slice(name.as_bytes());
            }
        }
        _ => return Err("a shim fetches a kernel and an initramfs, or nothing".into()),
    }
    Ok(data)
}

pub(crate) fn shim(
    blob: &[u8],
    entry: u64,
    spans: &[boot::Region],
    fetch: &[Fetch],
    lazy: u64,
) -> Result<Vec<u8>, String> {
    let data = data_block(entry, spans, fetch, lazy)?;
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

/// The 4-level map covering [0, MAP_LIMIT); `c_bit` is 0 on TDX and the C-bit
/// on SNP. It is measured, so it is built for the whole of MAP_LIMIT whatever
/// RAM the guest turns out to have: one PML4 entry and one PDPT of 1-GiB pages
/// per 512 GiB.
pub(crate) fn identity_map(c_bit: u64, shared_alias: bool) -> Vec<u8> {
    let c = if c_bit == 0 { 0 } else { 1u64 << c_bit };
    let pdpts = MAP_LIMIT / PDPT_SPAN;
    let pages = pdpts + 1 + u64::from(shared_alias);
    let mut v = vec![0u8; (pages * PAGE) as usize];
    for pdpt in 0..pdpts {
        let at = (pdpt * 8) as usize;
        put64(&mut v, at, (PAGE_TABLES + (pdpt + 1) * PAGE) | c | 3);
    }
    for gib in 0..MAP_LIMIT / GIB {
        put64(&mut v, (PAGE + gib * 8) as usize, (gib * GIB) | c | 0x83);
    }
    if shared_alias {
        // The slot above the mapped range -> a PDPT whose first entry is
        // physical GiB 0, unencrypted.
        let at = (pdpts * 8) as usize;
        put64(&mut v, at, (PAGE_TABLES + (pdpts + 1) * PAGE) | c | 3);
        put64(&mut v, ((pdpts + 1) * PAGE) as usize, 0x83);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot::RAM;
    use crate::vmsa::SNP_SHIM;

    // What the assembler made of each shim, so a test can hold its boot path to
    // the routines it runs rather than only to what those routines contain.
    const RESET_LISTING: &str = include_str!(concat!(env!("OUT_DIR"), "/reset.dis"));
    const SNP_LISTING: &str = include_str!(concat!(env!("OUT_DIR"), "/snp_reset.dis"));

    /// Every instruction objdump printed: where it is and what it says.
    fn listing(dis: &str) -> Vec<(u64, Vec<&str>)> {
        dis.lines()
            .filter_map(|line| {
                let (at, rest) = line.split_once(":\t")?;
                let at = u64::from_str_radix(at.trim(), 16).ok()?;
                let (_bytes, text) = rest.split_once('\t')?;
                Some((at, text.split_whitespace().collect()))
            })
            .collect()
    }

    /// The routine a call or jump names, and nothing for any other
    /// instruction. objdump names an address after whatever symbol precedes
    /// it, and layout.inc puts every address this image knows in the table, so
    /// a jump inside a routine is named after one of those rather than after
    /// the routine -- and with no offset at all where it lands on one exactly.
    /// Those are not routines, and this does not report them.
    fn target<'a>(text: &[&'a str]) -> Option<&'a str> {
        if !matches!(text.first(), Some(&"call") | Some(&"jmp")) {
            return None;
        }
        let name = text.last()?.strip_prefix('<')?.strip_suffix('>')?;
        match SYMBOLS
            .iter()
            .any(|(s, _)| *s == name.split('+').next().unwrap())
        {
            true => None,
            false => Some(name),
        }
    }

    /// Where each routine objdump named begins, in address order.
    fn symbols(dis: &str) -> Vec<(u64, &str)> {
        let mut v: Vec<(u64, &str)> = dis
            .lines()
            .filter_map(|line| {
                let (at, name) = line.split_once(" <")?;
                let at = u64::from_str_radix(at.trim(), 16).ok()?;
                Some((at, name.strip_suffix(">:")?))
            })
            .collect();
        v.sort_unstable();
        v
    }

    /// The routine an address falls in.
    fn routine<'a>(symbols: &[(u64, &'a str)], at: u64) -> &'a str {
        symbols
            .iter()
            .take_while(|(start, _)| *start <= at)
            .last()
            .map(|(_, name)| *name)
            .unwrap_or("")
    }

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
    /// On SNP the slot just above the mapped range reaches physical GiB 0 again
    /// with the C-bit clear, and nothing else.
    #[test]
    fn the_shared_alias_maps_gib_zero_unencrypted() {
        let pdpts = MAP_LIMIT / PDPT_SPAN;
        let m = identity_map(DEFAULT_CBIT as u64, true);
        assert_eq!(m.len() as u64, (pdpts + 2) * PAGE);
        let at = (pdpts * 8) as usize;
        let entry = u64::from_le_bytes(m[at..at + 8].try_into().unwrap());
        assert_eq!(
            entry,
            (PAGE_TABLES + (pdpts + 1) * PAGE) | 1 << DEFAULT_CBIT | 3
        );
        let alias = &m[((pdpts + 1) * PAGE) as usize..];
        assert_eq!(u64::from_le_bytes(alias[..8].try_into().unwrap()), 0x83);
        assert!(alias[8..].iter().all(|b| *b == 0));
        // The alias is the first address past the identity map, so nothing the
        // guest reaches through the map can reach it.
        assert_eq!(SHARED_ALIAS, pdpts * PDPT_SPAN);
    }

    /// Four PML4 entries, one per PDPT, each of 512 1-GiB pages: the map covers
    /// MAP_LIMIT whatever RAM the guest has, because it is measured.
    #[test]
    fn the_map_is_built_for_the_whole_limit_however_large_the_guest_is() {
        let m = identity_map(0, false);
        let pdpts = MAP_LIMIT / PDPT_SPAN;
        assert_eq!(m.len() as u64, (pdpts + 1) * PAGE);
        for pdpt in 0..pdpts {
            let at = (pdpt * 8) as usize;
            assert_eq!(
                u64::from_le_bytes(m[at..at + 8].try_into().unwrap()),
                (PAGE_TABLES + (pdpt + 1) * PAGE) | 3
            );
            // Every PDPT is full, so no 1-GiB slot below MAP_LIMIT is missing.
            assert_eq!(pdpte(&m, pdpt * PDPT_SPAN), (pdpt * PDPT_SPAN) | 0x83);
            assert_eq!(
                pdpte(&m, (pdpt + 1) * PDPT_SPAN - GIB),
                ((pdpt + 1) * PDPT_SPAN - GIB) | 0x83
            );
        }
        assert!(m[(pdpts * 8) as usize..PAGE as usize]
            .iter()
            .all(|b| *b == 0));
    }
    /// map.inc and madt.inc are held to boot.rs and acpi.rs by tests that run
    /// them. Nothing in those tests says the shim runs them: a routine the boot
    /// path never calls, or calls in the wrong order, or hands to the wrong
    /// primitive, assembles and passes exactly as well as one it does. That is
    /// the half of "measured assembly nothing ever executed" a harness cannot
    /// reach, so it is asserted against what the assembler actually emitted.
    #[test]
    fn each_shim_runs_the_routines_it_is_built_from() {
        for (blob, dis, entered, accept) in [
            (RESET_SHIM, RESET_LISTING, "long_mode", "accept_lazy"),
            (SNP_SHIM, SNP_LISTING, "snp_long_mode", "accept_lazy"),
        ] {
            let code = listing(dis);
            let symbols = symbols(dis);
            // The listing describes the page that is measured, not some other build.
            assert_eq!(
                code.len(),
                code.iter().filter(|(at, _)| *at < SHIM_SIZE).count(),
                "the listing runs past the shim page"
            );
            let calls: Vec<(u64, &str)> = code
                .iter()
                .filter_map(|(at, text)| target(text).map(|name| (*at, name)))
                .collect();
            let sites = |name: &str| -> Vec<u64> {
                calls
                    .iter()
                    .filter(|(_, n)| *n == name)
                    .map(|(at, _)| *at)
                    .collect()
            };

            // The boot path runs these once each, in this order.
            let mut last = 0;
            for name in ["host_regions", "merge_regions", "e820_build", "accept_walk"] {
                let at = sites(name);
                assert_eq!(at.len(), 1, "{name} is reached from {} places", at.len());
                assert_eq!(
                    routine(&symbols, at[0]),
                    entered,
                    "{name} is not on the boot path"
                );
                assert!(at[0] > last, "{name} runs out of order");
                last = at[0];
            }

            // ...and e820_build is given the zero page it writes the table into.
            let at = code
                .iter()
                .position(|(_, text)| target(text) == Some("e820_build"))
                .unwrap();
            assert_eq!(
                code[at - 1].1,
                ["mov", &format!("${ZERO_PAGE:#x},%edi")],
                "e820_build is handed something other than the zero page"
            );

            // accept_walk hands its ranges to this platform's own primitive and
            // to nothing else: once from the loop, once as it tails out.
            let from_walk: Vec<&str> = calls
                .iter()
                .filter(|(at, name)| routine(&symbols, *at) == "accept_walk" && !name.contains('+'))
                .map(|(_, name)| *name)
                .collect();
            assert_eq!(
                from_walk,
                [accept, accept],
                "accept_walk hands ranges elsewhere"
            );

            // The shim page really is what the listing describes.
            let (at, text) = &code[code.len() - 1];
            assert!(*at < SHIM_SIZE && !text.is_empty() && !blob.is_empty());
        }
    }

    /// Only the SNP shim converts memory, and the order is the whole of it:
    /// the block is shared before the walk that needs it and handed back after,
    /// and each range is made private before it is validated. A psc_range that
    /// ran after its PVALIDATE, or a walk that ran before the block was
    /// shared, assembles and passes every other test exactly as well.
    #[test]
    fn only_the_snp_shim_converts_memory_and_it_does_so_before_it_validates() {
        let tdx = symbols(RESET_LISTING);
        let (code, snp) = (listing(SNP_LISTING), symbols(SNP_LISTING));
        let symbols = &snp;
        let calls: Vec<(u64, &str)> = code
            .iter()
            .filter_map(|(at, text)| target(text).map(|name| (*at, name)))
            .collect();
        let sites = |name: &str| -> Vec<u64> {
            calls
                .iter()
                .filter(|(_, n)| *n == name)
                .map(|(at, _)| *at)
                .collect()
        };
        let once = |name: &str| -> u64 {
            let at = sites(name);
            assert_eq!(at.len(), 1, "{name} is reached from {} places", at.len());
            at[0]
        };
        // Shared, fetched into, walked, handed back, all on the boot path in
        // that order: the fetch talks to the host through the block too.
        let share = once("ghcb_share");
        let fetch = once("fetch_all");
        let walk = once("accept_walk");
        let private = once("ghcb_private");
        for at in [share, fetch, walk, private] {
            assert_eq!(
                routine(symbols, at),
                "snp_long_mode",
                "{at:#x} is off the boot path"
            );
        }
        assert!(
            share < fetch && fetch < walk && walk < private,
            "the block is shared out of order"
        );

        // Two conversions and no others: accept_private's, asking for private
        // and validating after, and fetch_all's, asking for the bounce buffer
        // shared and validating nothing. Each states its operation in %ebx
        // immediately before it calls.
        let psc = sites("psc_range");
        assert_eq!(
            psc.len(),
            2,
            "psc_range is reached from {} places",
            psc.len()
        );
        let asks = |at: u64| -> &[&str] {
            let n = code.iter().position(|(a, _)| *a == at).unwrap();
            &code[n - 1].1
        };
        let private_op = format!("${PSC_ENTRY_PRIVATE:#x},%ebx");
        let shared_op = format!("${PSC_ENTRY_SHARED:#x},%ebx");
        for at in psc {
            match routine(symbols, at) {
                "accept_private" => {
                    assert_eq!(asks(at), ["mov", &private_op[..]]);
                    let validate = calls
                        .iter()
                        .find(|(a, n)| {
                            routine(symbols, *a) == "accept_private" && *n == "validate_range"
                        })
                        .expect("accept_private never validates");
                    assert!(
                        at < validate.0,
                        "the range is validated before it is private"
                    );
                }
                "fetch_all" => assert_eq!(asks(at), ["mov", &shared_op[..]]),
                other => panic!("psc_range is reached from {other}"),
            }
        }

        // The walk's ranges reach PVALIDATE through accept_lazy, which hands
        // whatever it accepts to accept_private and to nothing else, and the
        // bitmap it marks is sized before the walk starts.
        let lazy: Vec<&str> = calls
            .iter()
            .filter(|(at, _)| routine(symbols, *at) == "accept_lazy")
            .map(|(_, name)| *name)
            .collect();
        assert_eq!(lazy, ["accept_private", "accept_private"]);
        let size = once("unaccepted_size");
        assert_eq!(routine(symbols, size), "snp_long_mode");
        assert!(size < walk, "the bitmap is sized after the walk marks it");

        // The TDX shim asks a host for nothing: it is handed accepted memory,
        // and measures the kernel and initramfs rather than fetching them.
        for name in [
            "psc_range",
            "psc_complete",
            "psc_vmgexit",
            "ghcb_share",
            "ghcb_private",
            "fetch_all",
            "fwcfg_dma",
            "ioio_out",
            "sha256",
        ] {
            assert!(
                !tdx.iter().any(|(_, n)| *n == name),
                "the TDX shim carries {name}"
            );
        }
    }

    /// Only the TDX shim starts application processors through the ACPI wakeup
    /// mailbox, so only its MADT carries the structure that names one.
    #[test]
    fn only_the_tdx_shim_builds_a_wakeup_structure() {
        let wakeup = format!("${:#x},(%rdi)", (MADT_WAKEUP_LEN << 8) | MADT_WAKEUP);
        let writes = |dis| {
            listing(dis)
                .iter()
                .any(|(_, text)| text.first() == Some(&"movl") && text.get(1) == Some(&&wakeup[..]))
        };
        assert!(
            writes(RESET_LISTING),
            "the TDX MADT has no wakeup structure"
        );
        assert!(
            !writes(SNP_LISTING),
            "the SNP MADT carries a wakeup structure"
        );
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
            let spans = boot::shim_spans(&placed);
            let (top, host) = boot::host_regions(&params.extents());
            for (_, hi) in boot::accept_ranges(&boot::merge(&spans, &host), top) {
                assert_eq!(pdpte(&map, hi - PAGE) & 1, 1, "{hi:#x} is unmapped");
            }
        }
        assert!(Params::snp(MAX_RAM + PAGE, DEFAULT_VCPUS, DEFAULT_CBIT, "").is_err());
    }

    /// The setup sectors the shim skips, which are measured in their own pages.
    const SETUP: usize = 0x1000;

    /// Bytes no two tests share, so one that read another's leftovers would fail.
    fn bytes(len: usize, seed: u32) -> Vec<u8> {
        (0..len as u32)
            .map(|i| {
                (i.wrapping_mul(2654435761) ^ seed.wrapping_mul(40503)).rotate_left(seed % 31) as u8
            })
            .collect()
    }

    /// A kernel file whose payload runs past one bounce buffer, so the shim
    /// has to fetch it in pieces, and an initramfs that ends mid-page.
    fn files(seed: u32) -> (Vec<u8>, Vec<u8>) {
        (
            bytes(SETUP + FETCH_BOUNCE_SIZE as usize + 0x1234, seed),
            bytes(300_001, seed + 1),
        )
    }

    /// The shim, with a data block stating what these two files hash to.
    fn fetching(kernel: &[u8], initrd: &[u8]) -> crate::shim::Shim {
        let shim = crate::shim::shim();
        let fetch = [
            Fetch::of(KERNEL_BASE, SETUP as u64, &kernel[SETUP..]),
            Fetch::of(INITRAMFS_BASE, 0, initrd),
        ];
        shim.data_fetching(KERNEL_BASE + boot::ENTRY_64_OFFSET, &[], &fetch);
        shim
    }

    /// A device serving the two files among others, before and after them.
    fn serving(kernel: &[u8], initrd: &[u8]) -> crate::shim::Device {
        crate::shim::Device::Serves(vec![
            ("bootorder".into(), vec![1, 2, 3]),
            (FWCFG_KERNEL.into(), kernel.to_vec()),
            ("etc/e820".into(), vec![0; 40]),
            (FWCFG_INITRD.into(), initrd.to_vec()),
            ("opt/tinfoil/kernel2".into(), vec![9; 10]),
        ])
    }

    /// The assembly the SNP shim hashes with, held to the standard at every
    /// length where the padding changes shape and well past one block.
    #[test]
    fn the_shim_hashes_as_fips_180_4_does() {
        let (kernel, initrd) = files(1);
        let shim = fetching(&kernel, &initrd);
        for len in [
            0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000, 4096, 100_003,
        ] {
            let data = bytes(len, len as u32);
            assert_eq!(
                shim.sha256(&data),
                <[u8; 32]>::from(Sha256::digest(&data)),
                "a {len}-byte input"
            );
        }
    }

    /// Both files reach the memory Linux runs them from, each range accepted
    /// as private before anything is copied in, and the only conversion the
    /// fetch asks for is the bounce buffer, shared, in one 2-MiB entry.
    #[test]
    fn the_shim_fetches_both_files_and_holds_them_to_their_digests() {
        let (kernel, initrd) = files(2);
        let shim = fetching(&kernel, &initrd);
        let run = shim.fetch(serving(&kernel, &initrd));
        assert_eq!(
            run.result, 1,
            "a device serving the right files was refused"
        );
        let payload = &kernel[SETUP..];
        assert_eq!(shim.memory(KERNEL_BASE, payload.len() as u64), payload);
        assert_eq!(shim.memory(INITRAMFS_BASE, initrd.len() as u64), initrd);
        let end = |base: u64, len: usize| align_up(base + len as u64, PAGE);
        assert_eq!(
            run.accepted,
            [
                (KERNEL_BASE, end(KERNEL_BASE, payload.len())),
                (INITRAMFS_BASE, end(INITRAMFS_BASE, initrd.len())),
            ]
        );
        assert_eq!(
            run.psc,
            [FETCH_BOUNCE | 1 << PSC_ENTRY_SHARED | 1 << PSC_ENTRY_LARGE],
            "the fetch converted something other than the bounce buffer"
        );
    }

    /// Every request the fetch makes of the host is a 32-bit OUT to the fw_cfg
    /// DMA register, stated as the GHCB specification has an IOIO exit stated:
    /// the exit code, both exit infos and RAX marked valid and nothing else,
    /// the GPA of the shim's own access, big-endian, high half first.
    #[test]
    fn every_port_write_is_an_ioio_exit_to_the_dma_register() {
        let (kernel, initrd) = files(3);
        let shim = fetching(&kernel, &initrd);
        let run = shim.fetch(serving(&kernel, &initrd));
        assert_eq!(run.result, 1);
        assert!(!run.writes.is_empty() && run.writes.len().is_multiple_of(2));
        let mut valid = [0u8; 16];
        valid[GHCB_VALID_BYTE as usize] = GHCB_IOIO_VALID_BITS as u8;
        valid[GHCB_RAX_VALID_BYTE as usize] |= GHCB_RAX_VALID_BIT as u8;
        for (n, w) in run.writes.iter().enumerate() {
            let (port, value) = match n % 2 {
                0 => (FWCFG_PORT_DMA, 0),
                _ => (FWCFG_PORT_DMA + 4, (FWCFG_DMA_GPA as u32).swap_bytes()),
            };
            assert_eq!((w.port as u64, w.value), (port, value), "write {n}");
            assert!(w.rax_valid);
            assert_eq!(w.ghcb.exit_code, SVM_EXIT_IOIO);
            assert_eq!(w.ghcb.exit_info_1, port << 16 | IOIO_SZ32 | IOIO_A64);
            assert_eq!(w.ghcb.exit_info_2, 0);
            assert_eq!(w.ghcb.valid, valid);
            assert_eq!((w.ghcb.usage, w.ghcb.protocol), (0, GHCB_PROTOCOL as u16));
        }
    }

    /// One byte wrong anywhere the shim copies is a guest that never runs it.
    /// The setup sectors are not among those bytes -- they are measured in
    /// their own pages, and the shim skips them in the file.
    #[test]
    fn bytes_that_do_not_hash_to_the_measured_digest_are_refused() {
        let (kernel, initrd) = files(4);
        let shim = fetching(&kernel, &initrd);
        for at in [SETUP, SETUP + FETCH_BOUNCE_SIZE as usize, kernel.len() - 1] {
            let mut bad = kernel.clone();
            bad[at] ^= 1;
            assert_eq!(
                shim.fetch(serving(&bad, &initrd)).result,
                2,
                "kernel byte {at:#x}"
            );
        }
        let mut bad = initrd.clone();
        bad[initrd.len() / 2] ^= 0x80;
        assert_eq!(shim.fetch(serving(&kernel, &bad)).result, 2, "initramfs");
        let mut setup = kernel.clone();
        setup[SETUP - 1] ^= 1;
        assert_eq!(shim.fetch(serving(&setup, &initrd)).result, 1);
    }

    /// A file of any other length is another file, and is refused before a
    /// byte of it is copied; so is a name that only begins like the right one,
    /// a directory longer than the shim reads, and a device that will not serve.
    #[test]
    fn a_device_that_does_not_serve_exactly_these_files_is_refused() {
        use crate::shim::Device;
        let (kernel, initrd) = files(5);
        let shim = fetching(&kernel, &initrd);
        let mut longer = kernel.clone();
        longer.push(0);
        assert_eq!(
            shim.fetch(serving(&longer, &initrd)).result,
            0,
            "a longer kernel"
        );
        assert_eq!(
            shim.fetch(serving(&kernel, &initrd[..initrd.len() - 1]))
                .result,
            0,
            "a shorter initramfs"
        );
        let missing = Device::Serves(vec![
            (FWCFG_KERNEL.into(), kernel.clone()),
            ("opt/tinfoil/initrd2".into(), initrd.clone()),
        ]);
        let run = shim.fetch(missing);
        assert_eq!(run.result, 0, "an initramfs under another name");
        let mut crowded: Vec<(String, Vec<u8>)> = (0..FETCH_DIR_ENTRIES)
            .map(|n| (format!("etc/{n}"), vec![0]))
            .collect();
        crowded.push((FWCFG_KERNEL.into(), kernel.clone()));
        crowded.push((FWCFG_INITRD.into(), initrd.clone()));
        assert_eq!(
            shim.fetch(Device::Serves(crowded)).result,
            0,
            "a directory past the read"
        );
        assert_eq!(
            shim.fetch(Device::DmaError).result,
            0,
            "a failed DMA access"
        );
        assert_eq!(
            shim.fetch(Device::Refuses).result,
            0,
            "a refused port write"
        );
    }

    /// The names the shim looks for are the ones the builder publishes, each
    /// with the NUL the shim compares as part of it.
    #[test]
    fn the_snp_shim_fetches_the_files_the_builder_names() {
        let fetch = [
            Fetch::of(KERNEL_BASE, 0, &[1]),
            Fetch::of(INITRAMFS_BASE, 0, &[2]),
        ];
        let block = data_block(0, &[], &fetch, KERNEL_BASE).unwrap();
        for (n, name) in ["opt/tinfoil/kernel", "opt/tinfoil/initrd"]
            .iter()
            .enumerate()
        {
            let at = (SHIM_DATA_FETCH + n as u64 * FETCH_LEN + FETCH_NAME) as usize;
            assert_eq!(
                &block[at..at + FETCH_NAME_LEN as usize],
                [name.as_bytes(), &[0]].concat()
            );
        }
    }
}

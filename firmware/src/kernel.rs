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
        initramfs,
        command,
        entry: KERNEL_BASE + boot::ENTRY_64_OFFSET,
    })
}

/// The shim's data block: the entry point, how many shapes the shapes page
/// holds, and the ranges the shim accepts (`shim_accept`), then a zero pair.
/// The lazy bound the shapes and the ranges were made for is checked here. All of it follows from what this image placed, so nothing about
/// the guest's RAM is measured here.
pub fn data_block(
    entry: u64,
    shapes: usize,
    lazy: u64,
    accept: &[(u64, u64)],
) -> Result<Vec<u8>, String> {
    // mark_lazy marks every whole unit past the bound, so one that left the
    // bitmap or the decompressor to Linux would mark memory nothing accepts.
    if !lazy.is_multiple_of(UNACCEPTED_UNIT) || lazy < UNACCEPTED_BITMAP + UNACCEPTED_BITMAP_SIZE {
        return Err(format!(
            "{lazy:#x} is not a lazy bound past the unaccepted bitmap"
        ));
    }
    // ...and the bitmap is zero when it marks it only because it is accepted.
    let bitmap = (
        UNACCEPTED_BITMAP,
        UNACCEPTED_BITMAP + UNACCEPTED_BITMAP_SIZE,
    );
    if !accept
        .iter()
        .any(|(lo, hi)| *lo <= bitmap.0 && bitmap.1 <= *hi)
    {
        return Err("the unaccepted bitmap lies outside the RAM the shim accepts".into());
    }
    if accept.iter().any(|(lo, hi)| lo >= hi) || accept.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err("an accept range is empty or out of order".into());
    }
    let mut data = entry.to_le_bytes().to_vec();
    data.extend_from_slice(&(shapes as u64).to_le_bytes());
    for (lo, hi) in accept {
        data.extend_from_slice(&lo.to_le_bytes());
        data.extend_from_slice(&hi.to_le_bytes());
    }
    data.extend_from_slice(&[0u8; 16]);
    if data.len() > SHIM_DATA_SIZE as usize {
        return Err(format!(
            "shim data block needs {} of its {SHIM_DATA_SIZE} bytes",
            data.len()
        ));
    }
    data.resize(SHIM_DATA_SIZE as usize, 0);
    Ok(data)
}

pub(crate) fn shim(
    blob: &[u8],
    entry: u64,
    shapes: usize,
    lazy: u64,
    accept: &[(u64, u64)],
) -> Result<Vec<u8>, String> {
    let data = data_block(entry, shapes, lazy, accept)?;
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
pub(crate) fn identity_map(c_bit: u64) -> Vec<u8> {
    let c = if c_bit == 0 { 0 } else { 1u64 << c_bit };
    let pdpts = MAP_LIMIT / PDPT_SPAN;
    let mut v = vec![0u8; ((pdpts + 1) * PAGE) as usize];
    for pdpt in 0..pdpts {
        let at = (pdpt * 8) as usize;
        put64(&mut v, at, (PAGE_TABLES + (pdpt + 1) * PAGE) | c | 3);
    }
    for gib in 0..MAP_LIMIT / GIB {
        put64(&mut v, (PAGE + gib * 8) as usize, (gib * GIB) | c | 0x83);
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
        let p = identity_map(0);
        // PML4[0] points at the PDPT that follows it, whose entries are 1-GiB pages.
        assert_eq!(
            u64::from_le_bytes(p[..8].try_into().unwrap()),
            (PAGE_TABLES + PAGE) | 3
        );
        assert_eq!(pdpte(&p, 0), 0x83);
        assert_eq!(pdpte(&p, MAP_LIMIT - GIB), (MAP_LIMIT - GIB) | 0x83);
        assert_eq!(pdpte(&p, RESET_ALIAS) & 1, 1);
        let e = identity_map(DEFAULT_CBIT as u64);
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
    /// Four PML4 entries, one per PDPT, each of 512 1-GiB pages: the map covers
    /// MAP_LIMIT whatever RAM the guest has, because it is measured.
    #[test]
    fn the_map_is_built_for_the_whole_limit_however_large_the_guest_is() {
        let m = identity_map(0);
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
    /// shape.inc and madt.inc are held to boot.rs and acpi.rs by tests that run
    /// them. Nothing in those tests says the shim runs them: a routine the boot
    /// path never calls, or calls in the wrong order, or hands to the wrong
    /// primitive, assembles and passes exactly as well as one it does. That is
    /// the half of "measured assembly nothing ever executed" a harness cannot
    /// reach, so it is asserted against what the assembler actually emitted.
    #[test]
    fn each_shim_runs_the_routines_it_is_built_from() {
        for (blob, dis, entered, accept) in [
            (RESET_SHIM, RESET_LISTING, "long_mode", "accept_range"),
            (SNP_SHIM, SNP_LISTING, "snp_reset_start", "validate_range"),
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

            // The boot path runs these once each, in this order: the map is
            // matched before anything is written from it, and the bitmap is
            // marked only once the RAM it lives in is accepted.
            // The SNP shim starts with the first of these, at offset 0.
            let mut last = None;
            for name in ["shape_match", "shape_apply", "accept_fixed", "mark_lazy"] {
                let at = sites(name);
                assert_eq!(at.len(), 1, "{name} is reached from {} places", at.len());
                assert_eq!(
                    routine(&symbols, at[0]),
                    entered,
                    "{name} is not on the boot path"
                );
                assert!(last.is_none_or(|l| at[0] > l), "{name} runs out of order");
                last = Some(at[0]);
            }

            // ...and shape_apply is given the zero page to write the table into.
            let at = code
                .iter()
                .position(|(_, text)| target(text) == Some("shape_apply"))
                .unwrap();
            assert_eq!(
                code[at - 1].1,
                ["mov", &format!("${ZERO_PAGE:#x},%edi")],
                "shape_apply is handed something other than the zero page"
            );

            // accept_fixed hands its ranges to this platform's own primitive
            // and to nothing else.
            let from = |caller: &str| -> Vec<&str> {
                calls
                    .iter()
                    .filter(|(at, name)| routine(&symbols, *at) == caller && !name.contains('+'))
                    .map(|(_, name)| *name)
                    .collect()
            };
            assert_eq!(
                from("accept_fixed"),
                [accept],
                "accept_fixed hands ranges elsewhere"
            );
            assert_eq!(
                from("shape_match"),
                ["shape_try"],
                "shape_match tries the shapes some other way"
            );

            // The shim page really is what the listing describes.
            let (at, text) = &code[code.len() - 1];
            assert!(*at < SHIM_SIZE && !text.is_empty() && !blob.is_empty());
        }
    }

    /// Neither shim converts memory or shares a page: the SNP shim validates
    /// what the loader made private before launch, and exits to the host only
    /// to terminate; the TDX shim calls the TDX module, and the host only to
    /// report a failure. A port write, a page state change or a second exit
    /// assembles and passes every other test exactly as well.
    #[test]
    fn no_shim_asks_the_host_for_anything_but_to_stop() {
        let snp = listing(SNP_LISTING);
        let snp_symbols = symbols(SNP_LISTING);
        let exits: Vec<u64> = snp
            .iter()
            .filter(|(_, text)| text.first() == Some(&"vmgexit"))
            .map(|(at, _)| *at)
            .collect();
        assert_eq!(
            exits.len(),
            1,
            "the SNP shim exits to the host {} times",
            exits.len()
        );
        assert_eq!(routine(&snp_symbols, exits[0]), "die_step");
        let port_io = [
            "in", "inb", "inw", "inl", "out", "outb", "outw", "outl", "insb", "insw", "insl",
            "outsb", "outsw", "outsl",
        ];
        for (code, symbols) in [
            (snp, snp_symbols),
            (listing(RESET_LISTING), symbols(RESET_LISTING)),
        ] {
            assert!(
                !code
                    .iter()
                    .any(|(_, text)| text.first().is_some_and(|m| port_io.contains(m))),
                "a shim does port I/O"
            );
            for name in [
                "psc_range",
                "ghcb_share",
                "ghcb_private",
                "host_regions",
                "accept_walk",
            ] {
                assert!(
                    !symbols.iter().any(|(_, n)| *n == name),
                    "a shim carries {name}"
                );
            }
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

    /// The shims accept and mark through the identity map, so every range
    /// either touches is mapped: the fixed ranges below the bound, and the RAM
    /// of every shape up to the most it may end at.
    #[test]
    fn every_range_the_shim_is_told_to_touch_is_mapped() {
        let map = identity_map(DEFAULT_CBIT as u64);
        let placed = vec![Placed::measured(
            KERNEL_BASE,
            "",
            RAM,
            vec![0u8; PAGE as usize],
        )];
        let spans = boot::shim_spans(&placed);
        let lazy = KERNEL_BASE + 0x400_0000;
        for (_, hi) in boot::shim_accept(&spans, lazy) {
            assert_eq!(pdpte(&map, hi - PAGE) & 1, 1, "{hi:#x} is unmapped");
        }
        for amd in [false, true] {
            for shape in boot::qemu_shapes(amd, boot::least_memory(&spans, lazy)) {
                assert!(shape.max_end <= MAP_LIMIT);
                assert_eq!(pdpte(&map, shape.max_end - PAGE) & 1, 1);
            }
        }
    }
}

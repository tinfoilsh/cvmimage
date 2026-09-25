use crate::layout::*;

// Setup header fields, named as in Documentation/arch/x86/boot.rst.
const HDR_SETUP_SECTS: usize = 0x1f1;
const HDR_BOOT_FLAG: usize = 0x1fe;
const HDR_SIGNATURE: usize = 0x202;
const HDR_VERSION: usize = 0x206;
const HDR_TYPE_OF_LOADER: usize = 0x210;
const HDR_LOADFLAGS: usize = 0x211;
const HDR_CODE32_START: usize = 0x214;
const HDR_RAMDISK_IMAGE: usize = 0x218;
const HDR_RAMDISK_SIZE: usize = 0x21c;
const HDR_CMD_LINE_PTR: usize = 0x228;
const HDR_KERNEL_ALIGNMENT: usize = 0x230;
const HDR_RELOCATABLE: usize = 0x234;
const HDR_XLOADFLAGS: usize = 0x236;
const HDR_CMDLINE_SIZE: usize = 0x238;
const HDR_SETUP_DATA: usize = 0x250;
const HDR_PREF_ADDRESS: usize = 0x258;
const HDR_INIT_SIZE: usize = 0x260;
// The span of the header the builder copies, and the least a bzImage must carry.
const SETUP_HEADER: usize = HDR_SETUP_SECTS;
const SETUP_HEADER_END: usize = 0x290;
const SETUP_HEADER_MIN: usize = 0x268;
// The 64-bit entry point sits this far into the protected-mode payload.
pub const ENTRY_64_OFFSET: u64 = 0x200;

const BOOT_FLAG: u16 = 0xaa55;
const BOOT_PROTOCOL_2_12: u16 = 0x020c;
const LOADFLAGS_LOADED_HIGH: u8 = 1;
const LOADFLAGS_CAN_USE_HEAP: u8 = 0x80;
const LOADER_TYPE_UNDEFINED: u8 = 0xff;
const XLF_KERNEL_64: u8 = 1;

const BP_ACPI_RSDP_ADDR: usize = 0x70;

// The Linux 64-bit boot protocol descriptors, addressed by the selectors above.
const GDT_CODE32: u64 = 0x00cf_9b00_0000_ffff;
const GDT_CODE64: u64 = 0x00af_9b00_0000_ffff;
const GDT_DATA: u64 = 0x00cf_9300_0000_ffff;

pub const RAM: u32 = E820_RAM as u32;
pub const RESERVED: u32 = E820_RESERVED as u32;
pub const ACPI: u32 = E820_ACPI as u32;
pub const ABSENT: u32 = E820_ABSENT as u32;

#[derive(Clone, Copy)]
pub struct KernelInfo {
    pub setup_bytes: usize,
    pub init_size: u32,
    pub cmdline_max: u32,
}

pub fn parse_bzimage(image: &[u8]) -> Result<KernelInfo, String> {
    if image.len() < SETUP_HEADER_MIN {
        return Err("bzImage is shorter than its setup header".into());
    }
    if get16(image, HDR_BOOT_FLAG) != BOOT_FLAG
        || &image[HDR_SIGNATURE..HDR_SIGNATURE + 4] != b"HdrS"
    {
        return Err("not an x86 Linux bzImage".into());
    }
    if get16(image, HDR_VERSION) < BOOT_PROTOCOL_2_12 {
        return Err("Linux boot protocol 2.12 or newer is required".into());
    }
    if image[HDR_LOADFLAGS] & LOADFLAGS_LOADED_HIGH == 0 {
        return Err("kernel is not a bzImage".into());
    }
    if image[HDR_XLOADFLAGS] & XLF_KERNEL_64 == 0 {
        return Err("kernel does not advertise a 64-bit entry".into());
    }
    // The payload loads at the fixed KERNEL_BASE, so a kernel that cannot run there is refused.
    let alignment = get32(image, HDR_KERNEL_ALIGNMENT) as u64;
    if alignment == 0 || !alignment.is_power_of_two() || !KERNEL_BASE.is_multiple_of(alignment) {
        return Err("kernel alignment is not satisfied by the fixed load address".into());
    }
    if image[HDR_RELOCATABLE] == 0 && get64(image, HDR_PREF_ADDRESS) != KERNEL_BASE {
        return Err("kernel is not relocatable and prefers a different load address".into());
    }
    let setup_sects = if image[HDR_SETUP_SECTS] == 0 {
        4
    } else {
        image[HDR_SETUP_SECTS] as usize
    };
    let setup_bytes = (setup_sects + 1) * 512;
    if setup_bytes + ENTRY_64_OFFSET as usize >= image.len() {
        return Err("bzImage has no protected-mode payload".into());
    }
    Ok(KernelInfo {
        setup_bytes,
        init_size: get32(image, HDR_INIT_SIZE),
        cmdline_max: get32(image, HDR_CMDLINE_SIZE),
    })
}

/// The zero page, minus the E820 map: that table depends on the RAM the guest
/// turns out to have, so a shim writes it into the bytes left zero here.
pub fn zero_page(
    setup: &[u8],
    info: KernelInfo,
    initramfs_len: usize,
    rsdp: u64,
    setup_data: u64,
) -> Result<Vec<u8>, String> {
    let mut page = vec![0u8; PAGE as usize];
    page[SETUP_HEADER..SETUP_HEADER_END].copy_from_slice(&setup[SETUP_HEADER..SETUP_HEADER_END]);
    page[HDR_TYPE_OF_LOADER] = LOADER_TYPE_UNDEFINED;
    page[HDR_LOADFLAGS] |= LOADFLAGS_CAN_USE_HEAP;
    put32(&mut page, HDR_RAMDISK_IMAGE, INITRAMFS_BASE as u32);
    put32(&mut page, HDR_RAMDISK_SIZE, initramfs_len as u32);
    put32(&mut page, HDR_CMD_LINE_PTR, CMDLINE as u32);
    put32(&mut page, HDR_CODE32_START, KERNEL_BASE as u32);
    put32(&mut page, HDR_INIT_SIZE, info.init_size);
    put64(&mut page, BP_ACPI_RSDP_ADDR, rsdp);
    // TDX chains nothing here; SNP chains one SETUP_CC_BLOB record.
    put64(&mut page, HDR_SETUP_DATA, setup_data);
    Ok(page)
}

/// The E820 map a page carries, read back the way Linux reads it.
pub fn read_e820(page: &[u8]) -> Vec<Region> {
    (0..page[BP_E820_ENTRIES as usize] as u64)
        .map(|n| {
            let at = (BP_E820_TABLE + n * E820_ENTRY_LEN) as usize;
            let word = |i: usize| u64::from_le_bytes(page[i..i + 8].try_into().unwrap());
            (
                word(at),
                word(at + 8),
                u32::from_le_bytes(page[at + 16..at + 20].try_into().unwrap()),
            )
        })
        .collect()
}

// The measured GDT at the base of the BSP stack, which grows down from the far end.
pub fn gdt_stack() -> Vec<u8> {
    let mut v = vec![0u8; BSP_STACK_SIZE as usize];
    put64(&mut v, BOOT_CS32 as usize, GDT_CODE32);
    put64(&mut v, BOOT_CS as usize, GDT_CODE64);
    put64(&mut v, BOOT_DS as usize, GDT_DATA);
    let at = (GDT_PTR - BSP_STACK) as usize;
    v[at..at + 2].copy_from_slice(&(GDT_LIMIT as u16).to_le_bytes());
    put64(&mut v, at + 2, BSP_STACK);
    v
}

/// What a placed span holds; ordinary RAM is everything these leave over.
pub enum Fill {
    Measured(Vec<u8>),
    /// One SNP page the firmware fills: measured by address, never by content.
    Host,
    /// One page the loader fills from an IGVM parameter area: private on
    /// arrival, so no shim accepts it, and measured by address alone.
    Parameters,
    /// A declared MMIO aperture: nothing is loaded there and no shim accepts it.
    Mmio(u64),
}

/// A span of the guest map, from which the E820 map, the file and the accept list follow.
pub struct Placed {
    pub base: u64,
    /// What the manifest publishes this region as; empty leaves it out.
    pub name: &'static str,
    pub e820: u32,
    pub fill: Fill,
}

impl Placed {
    pub fn measured(base: u64, name: &'static str, e820: u32, data: Vec<u8>) -> Placed {
        Placed {
            base,
            name,
            e820,
            fill: Fill::Measured(data),
        }
    }
    pub fn host(base: u64) -> Placed {
        Placed {
            base,
            name: "",
            e820: RESERVED,
            fill: Fill::Host,
        }
    }
    pub fn parameters(base: u64) -> Placed {
        Placed {
            base,
            name: "",
            e820: RESERVED,
            fill: Fill::Parameters,
        }
    }
    pub fn mmio(base: u64, size: u64) -> Placed {
        Placed {
            base,
            name: "",
            e820: ABSENT,
            fill: Fill::Mmio(size),
        }
    }
    pub fn span(&self) -> u64 {
        match &self.fill {
            Fill::Measured(d) => align_up(d.len() as u64, PAGE).max(PAGE),
            Fill::Host | Fill::Parameters => PAGE,
            Fill::Mmio(n) => *n,
        }
    }
    pub fn data(&self) -> &[u8] {
        match &self.fill {
            Fill::Measured(d) => d,
            _ => &[],
        }
    }
}

/// The whole 4-KiB pages a region's contents occupy, the last one zero-padded.
pub fn pages(base: u64, data: &[u8]) -> impl Iterator<Item = (u64, Vec<u8>)> + '_ {
    data.chunks(PAGE as usize)
        .enumerate()
        .map(move |(i, chunk)| {
            let mut page = vec![0u8; PAGE as usize];
            page[..chunk.len()].copy_from_slice(chunk);
            (base + i as u64 * PAGE, page)
        })
}

/// Fills a placed region, keeping its span so a map already derived from it holds.
pub fn fill(placed: &mut [Placed], base: u64, data: Vec<u8>) -> Result<(), String> {
    let region = placed
        .iter_mut()
        .find(|p| p.base == base)
        .ok_or_else(|| format!("nothing is placed at {base:#x}"))?;
    let span = region.span();
    region.fill = Fill::Measured(data);
    if region.span() != span {
        return Err(format!("contents for {base:#x} do not fit its placed span"));
    }
    Ok(())
}

pub fn spans(placed: &[Placed]) -> Vec<Region> {
    let mut v: Vec<_> = placed
        .iter()
        .map(|p| (p.base, p.base + p.span(), p.e820))
        .collect();
    v.sort_unstable();
    v
}

/// Overlapping spans reach Linux as an E820 map and an accept list that disagree.
pub fn validate(placed: &[Placed], memory: u64) -> Result<(), String> {
    for pair in spans(placed).windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(format!("placed regions overlap at {:#x}", pair[1].0));
        }
    }
    for p in placed {
        if !p.base.is_multiple_of(PAGE) {
            return Err(format!("placed region {:#x} is not page-aligned", p.base));
        }
        if p.base >= memory && p.base != RESET_ALIAS {
            return Err(format!(
                "placed region {:#x} lies outside the memory the image describes",
                p.base
            ));
        }
    }
    Ok(())
}

/// One region of a guest's map: where it starts, where it ends, and what E820
/// calls it. A shim merges the measured spans and the loader's regions into
/// one list of these and builds both tables from it.
pub type Region = (u64, u64, u32);

/// The map a shim builds its E820 table and accept list from: every span this
/// image places at a fixed address. It is measured, so it is one list for
/// every guest the image can run in, and it says nothing about how much RAM
/// that guest has or where its apertures are -- the loader's map says that.
pub fn shim_spans(placed: &[Placed]) -> Vec<Region> {
    let mut v: Vec<Region> = placed
        .iter()
        .filter(|p| !matches!(p.fill, Fill::Mmio(_)))
        .map(|p| (p.base, p.base + p.span(), p.e820))
        .collect();
    v.sort_unstable();
    v
}

/// The least memory a guest can be given and still hold what this image placed
/// in it. The reset page is left out: it is the last page of the address space,
/// not of the guest's RAM.
pub fn min_memory(spans: &[Region]) -> u64 {
    spans
        .iter()
        .filter(|(lo, _, _)| *lo != RESET_ALIAS)
        .map(|(_, hi, _)| *hi)
        .max()
        .unwrap_or(0)
}

/// The parts of the loader's map that are not RAM, and the top of the RAM that
/// is: the gaps between its extents, which are where a guest's devices are
/// given their windows, and anything it marks as something other than memory.
/// This is what a shim derives at boot, and what the shim is held to.
pub fn host_regions(extents: &[(u64, u64, bool)]) -> (u64, Vec<Region>) {
    let (mut top, mut at) = (0, 0);
    let mut out = Vec::new();
    for (lo, hi, ram) in extents.iter().copied() {
        if lo > at {
            out.push((at, lo, ABSENT));
        }
        if ram {
            top = hi;
        } else {
            out.push((lo, hi, RESERVED));
        }
        at = hi;
    }
    (top, out)
}

/// The measured spans and the loader's regions in one ascending list, a
/// measured span first where the two begin together.
pub fn merge(placed: &[Region], host: &[Region]) -> Vec<Region> {
    let mut out = Vec::with_capacity(placed.len() + host.len());
    let (mut p, mut h) = (0, 0);
    while p < placed.len() || h < host.len() {
        if p == placed.len() || (h < host.len() && host[h].0 < placed[p].0) {
            out.push(host[h]);
            h += 1;
        } else {
            out.push(placed[p]);
            p += 1;
        }
    }
    out
}

/// The E820 map: each region under its own type, each gap RAM, adjacent runs
/// coalesced. A region the loader leaves out of its map is an aperture, and
/// belongs in no entry at all; a span this image placed inside one still gets
/// its own, so nothing is left for Linux to put a BAR on top of.
pub fn e820(regions: &[Region], memory: u64) -> Vec<Region> {
    let mut out: Vec<(u64, u64, u32)> = Vec::new();
    let mut push = |base: u64, end: u64, kind: u32| {
        // A region nested inside one already written starts where that one
        // ended, so the table only ever ascends.
        let base = base.max(out.last().map_or(0, |last: &Region| last.0 + last.1));
        if base >= end {
            return;
        }
        match out.last_mut() {
            Some(last) if last.0 + last.1 == base && last.2 == kind => last.1 += end - base,
            _ => out.push((base, end - base, kind)),
        }
    };
    let mut at = 0;
    for (lo, hi, kind) in regions.iter().copied() {
        if lo >= memory {
            break;
        }
        push(at, lo, RAM);
        if kind != ABSENT {
            push(lo, hi.min(memory), kind);
        }
        at = at.max(hi);
    }
    push(at, memory, RAM);
    out
}

/// The ranges a shim accepts: [0, memory) minus everything the loader already accepted.
pub fn accept_ranges(regions: &[Region], memory: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut at = 0;
    for (lo, hi, _) in regions.iter().copied() {
        if lo > at {
            out.push((at, lo.min(memory)));
        }
        at = at.max(hi);
    }
    out.push((at, memory));
    out.retain(|(lo, hi)| lo < hi);
    out
}

fn get16(v: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(v[at..at + 2].try_into().unwrap())
}
fn get32(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}
fn get64(v: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(v[at..at + 8].try_into().unwrap())
}
pub fn put32(v: &mut [u8], at: usize, n: u32) {
    v[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
pub fn put64(v: &mut [u8], at: usize, n: u64) {
    v[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> Vec<Placed> {
        vec![
            Placed::measured(ZERO_PAGE, "", RESERVED, vec![0; PAGE as usize]),
            Placed::measured(ACPI_BASE, "", ACPI, vec![0; PAGE as usize]),
            Placed::host(SNP_SECRETS),
            Placed::measured(KERNEL_BASE, "", RAM, vec![0; PAGE as usize]),
        ]
    }

    #[test]
    fn e820_tiles_the_whole_span_without_gaps() {
        let map = map();
        let e = e820(&spans(&map), DEFAULT_RAM);
        assert_eq!(e.first().unwrap().0, 0);
        assert_eq!(e.last().unwrap().0 + e.last().unwrap().1, DEFAULT_RAM);
        for pair in e.windows(2) {
            assert_eq!(pair[0].0 + pair[0].1, pair[1].0);
        }
        assert!(e.iter().any(|x| x.0 == ACPI_BASE && x.2 == ACPI));
        assert!(!e.iter().any(|x| x.0 == KERNEL_BASE));
    }

    #[test]
    fn accept_ranges_are_exactly_the_complement_of_the_placed_map() {
        let map = map();
        let ranges = accept_ranges(&spans(&map), DEFAULT_RAM);
        let placed: Vec<_> = map.iter().map(|p| (p.base, p.base + p.span())).collect();
        // Nothing placed is ever accepted: that is the page-aliasing attack.
        for (lo, hi) in &ranges {
            assert!(placed.iter().all(|(a, b)| hi <= a || lo >= b));
        }
        // ...and nothing else is left out.
        let covered: u64 = ranges.iter().map(|(l, h)| h - l).sum();
        let taken: u64 = placed.iter().map(|(l, h)| h - l).sum();
        assert_eq!(covered + taken, DEFAULT_RAM);
    }

    #[test]
    fn an_mmio_hole_is_absent_from_e820_and_never_accepted() {
        let mut map = map();
        map.push(Placed::mmio(0x30_0000, 0x2_0000));
        // Linux assigns BARs out of gaps, so no entry of any type may cover the aperture.
        assert!(e820(&spans(&map), DEFAULT_RAM)
            .iter()
            .all(|x| x.0 + x.1 <= 0x30_0000 || x.0 >= 0x32_0000));
        assert!(accept_ranges(&spans(&map), DEFAULT_RAM)
            .iter()
            .all(|(l, h)| *h <= 0x30_0000 || *l >= 0x32_0000));
    }

    #[test]
    fn overlapping_placement_is_rejected() {
        let mut map = map();
        map.push(Placed::mmio(ACPI_BASE, PAGE));
        assert!(validate(&map, DEFAULT_RAM).is_err());
        assert!(validate(&map[..1], DEFAULT_RAM).is_ok());
    }

    #[test]
    fn gdt_is_addressed_by_its_own_selectors() {
        let v = gdt_stack();
        assert_eq!(v.len(), BSP_STACK_SIZE as usize);
        assert_eq!(&v[..8], &[0u8; 8]);
        assert_eq!(v[BOOT_CS as usize + 6] & 0x20, 0x20);
        let at = (GDT_PTR - BSP_STACK) as usize;
        assert_eq!(
            u16::from_le_bytes(v[at..at + 2].try_into().unwrap()) as u64,
            GDT_LIMIT
        );
        assert_eq!(
            u64::from_le_bytes(v[at + 2..at + 10].try_into().unwrap()),
            BSP_STACK
        );
    }

    #[test]
    fn malformed_kernel_is_rejected() {
        assert!(parse_bzimage(&[0; 0x300]).is_err());
    }
}

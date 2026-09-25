// The fixed guest-physical layout, measured whole and shared with the reset shims.

macro_rules! layout {
    ($($(#[$attr:meta])* $name:ident = $value:expr;)*) => {
        $($(#[$attr])* pub const $name: u64 = $value;)*
        #[allow(dead_code)]
        pub const SYMBOLS: &[(&str, u64)] = &[$((stringify!($name), $name)),*];
    };
}

layout! {
    PAGE = 4096;
    GIB = 0x4000_0000;

    ZERO_PAGE = 0x0000_7000;
    CMDLINE = 0x0002_0000;
    ACPI_BASE = 0x000e_0000;
    // The two pages the loader fills and no shim accepts, both unmeasured: the
    // processor count, and the map of the machine the guest was given.
    PARAM_PAGE = 0x000e_1000;
    PARAM_MAP_PAGE = 0x000e_2000;
    MAILBOX = 0x000f_0000;
    SNP_CPUID = 0x000f_0000;
    SNP_SECRETS = 0x000f_1000;
    SNP_CC_BLOB = 0x000f_2000;
    PAGE_TABLES = 0x0010_0000;
    // The most either platform places: one PML4 page and the four PDPT pages of
    // 1-GiB pages that cover MAP_LIMIT, plus on SNP a further PDPT page aliasing
    // physical GiB 0 without the C-bit (see SHARED_ALIAS). TDX places the first
    // five only.
    PAGE_TABLE_SIZE = 6 * PAGE;
    BSP_STACK = 0x0010_7000;
    BSP_STACK_SIZE = 0x0001_0000;
    BSP_STACK_TOP = BSP_STACK + BSP_STACK_SIZE;
    // The page the SNP shim shares with the host as its GHCB, to wake the other processors.
    SNP_GHCB = 0x0011_7000;
    SHIM_BASE = 0x0012_0000;
    SHIM_SIZE = PAGE;
    KERNEL_SETUP_BASE = 0x0012_1000;
    KERNEL_SETUP_AREA_SIZE = 0x0002_f000;
    KERNEL_SETUP_END = KERNEL_SETUP_BASE + KERNEL_SETUP_AREA_SIZE;
    KERNEL_BASE = 0x0100_0000;
    INITRAMFS_BASE = 0x2000_0000;
    RESET_ALIAS = 0xffff_f000;
    SNP_VMSA = 0xffff_ffff_f000;

    // Linux 64-bit boot protocol selectors, each its own byte offset into the GDT.
    BOOT_CS32 = 0x08;
    BOOT_CS = 0x10;
    BOOT_DS = 0x18;
    // Four 8-byte entries: null, 32-bit code, 64-bit code, data.
    GDT_LIMIT = BOOT_DS + 7;
    // The 10-byte pseudo-descriptor follows the GDT, so a shim `lgdt`s without a stack.
    GDT_PTR = BSP_STACK + GDT_LIMIT + 1;

    // An SNP application processor launches from its own measured VMSA and parks
    // here until Linux recreates it through the GHCB AP-creation call.
    SHIM_AP_PARK = 0x0000_0b00;
    SNP_AP_ENTRY = SHIM_BASE + SHIM_AP_PARK;

    // Physical GiB 0 seen again through PML4[4] with the C-bit clear: how the SNP
    // shim writes the one page it has made shared.
    SHARED_ALIAS = 0x200_0000_0000;

    // The fixed part of the MADT, measured inside the shim page that builds the rest.
    SHIM_MADT = 0x0000_0b80;
    // Where each shim finds its data block: the kernel entry point, the least
    // memory this image can run in, and the spans it placed.
    SHIM_DATA = 0x0000_0c00;
    // The block runs to the reset vector; nothing else lives in the page.
    SHIM_DATA_SIZE = RESET_VECTOR - SHIM_DATA;
    // A TD fetches its first instruction from the last 16 bytes of this page.
    RESET_VECTOR = PAGE - 16;

    // The data block: two words, then the placed spans, then a zero one.
    SHIM_DATA_ENTRY = 0;
    SHIM_DATA_MIN_MEMORY = 8;
    SHIM_DATA_SPANS = 16;
    // One region of the guest's map: where it starts, where it ends, and what
    // E820 calls it. The measured spans and the loader's regions share a shape,
    // because a shim merges them into one list.
    SPAN_LEN = 24;
    SPAN_HI = 8;
    SPAN_KIND = 16;

    // Where a shim builds that list. Both buffers are inside the measured stack
    // page, so no shim writes anywhere the image did not already place.
    SHIM_HOST_REGIONS = BSP_STACK + 0x1000;
    SHIM_HOST_REGIONS_END = SHIM_HOST_REGIONS + 0x1000;
    SHIM_REGIONS = BSP_STACK + 0x2000;
    SHIM_REGIONS_END = SHIM_REGIONS + 0x1000;

    ACPI_XSDT = 0x100;
    ACPI_FADT = 0x200;
    ACPI_DSDT = 0x400;
    ACPI_MADT = 0x500;
    RSDP_LEN = 36;
    XSDT_LEN = 52;
    FADT_LEN = 276;
    // A DSDT of nothing but its header: this machine has no AML to run.
    DSDT_LEN = 36;
    MADT_HEADER_LEN = 44;
    MADT_LAPIC_LEN = 8;
    MADT_WAKEUP_LEN = 16;
    // The MADT entry types the shims write, and the flag that says a processor is usable.
    MADT_LOCAL_APIC = 0;
    MADT_WAKEUP = 16;
    LAPIC_ENABLED = 1;

    // boot_params, as in Documentation/arch/x86/zero-page.rst: the E820 map a
    // shim writes there, and the room the structure has for it.
    BP_E820_ENTRIES = 0x1e8;
    BP_E820_TABLE = 0x2d0;
    E820_ENTRY_LEN = 20;
    E820_MAX = 128;
    // The E820 types this image states. ABSENT is not one of them: it marks a
    // span that belongs in no entry at all.
    E820_ABSENT = 0;
    E820_RAM = 1;
    E820_RESERVED = 2;
    E820_ACPI = 3;

    // IGVM_VHS_MEMORY_MAP_ENTRY, and the whole page of them a loader may fill.
    MAP_ENTRY_LEN = 24;
    MAP_ENTRY_PAGES = 8;
    MAP_ENTRY_TYPE = 16;
    // The most of that map a shim reads. QEMU describes a q35 guest in a
    // handful of entries; a map longer than this is refused, not truncated.
    MAP_ENTRIES = 32;
    MAP_TYPE_MEMORY = 0;

    // The identity map reaches this far; past it a shim faults with no IDT installed.
    MAP_LIMIT = 2048 * GIB;
    // What one page-directory-pointer table of 1-GiB pages covers.
    PDPT_SPAN = 512 * GIB;
    FOUR_GIB = 4 * GIB;
    // q35 splits a guest this size or larger, opening a PCI aperture (hw/i386/pc_q35.c).
    Q35_SPLIT = 0xb000_0000;
    Q35_LOWMEM = 2 * GIB;
    // The highest map top this image describes, which MAX_RAM is the RAM behind.
    MAX_MEMORY = MAP_LIMIT;
}

pub const SHIM_LIMIT: usize = 256 * 1024;

// A split guest's map reaches 4 GiB plus the RAM that did not fit below the aperture.
pub const MAX_RAM: u64 = MAP_LIMIT - FOUR_GIB + Q35_LOWMEM;
const _: () = assert!(RESET_ALIAS < MAP_LIMIT);
const _: () = assert!(MAX_MEMORY == FOUR_GIB + MAX_RAM - Q35_LOWMEM);
// A shim reads the map as page numbers, so its bound is one too.
const _: () = assert!(MAX_MEMORY.is_multiple_of(PAGE));
// The E820 map a shim writes has to fit boot_params: a gap and a region
// apiece, plus the RAM above the last of them.
const _: () = assert!(BP_E820_TABLE + E820_MAX * E820_ENTRY_LEN <= PAGE);
// The map is read one entry past the last, to refuse one longer than this.
const _: () = assert!((MAP_ENTRIES + 1) * MAP_ENTRY_LEN <= PAGE);
// Each extent can leave a gap before it and a region of its own, and every
// measured span joins them; the merged list then has to fit its buffer too.
const _: () = assert!(2 * MAP_ENTRIES * SPAN_LEN <= SHIM_HOST_REGIONS_END - SHIM_HOST_REGIONS);
const _: () =
    assert!(SHIM_DATA_SIZE + 2 * MAP_ENTRIES * SPAN_LEN <= SHIM_REGIONS_END - SHIM_REGIONS);
// Both buffers sit in the stack page, clear of the stack itself.
const _: () =
    assert!(BSP_STACK + PAGE <= SHIM_HOST_REGIONS && SHIM_HOST_REGIONS_END <= SHIM_REGIONS);
const _: () = assert!(SHIM_REGIONS_END + PAGE <= BSP_STACK_TOP);

// A shim accepts the gaps between these regions, so they tile in the order it skips them.
const _: () = assert!(ACPI_BASE + PAGE == PARAM_PAGE && PARAM_PAGE + PAGE == PARAM_MAP_PAGE);
const _: () = assert!(PARAM_MAP_PAGE + PAGE <= MAILBOX);
const _: () = assert!(MAILBOX + PAGE <= PAGE_TABLES);
const _: () = assert!(SNP_CPUID + PAGE == SNP_SECRETS && SNP_SECRETS + PAGE == SNP_CC_BLOB);
const _: () = assert!(SNP_CC_BLOB + PAGE <= PAGE_TABLES);
const _: () = assert!(PAGE_TABLES + PAGE_TABLE_SIZE <= BSP_STACK);
const _: () = assert!(GDT_PTR + 10 <= BSP_STACK_TOP);
const _: () = assert!(BSP_STACK_TOP <= SNP_GHCB && SNP_GHCB + PAGE <= SHIM_BASE);
const _: () = assert!(SHARED_ALIAS == MAP_LIMIT);
// One PML4 page, one PDPT per PDPT_SPAN, and on SNP one more for the alias.
const _: () = assert!(MAP_LIMIT.is_multiple_of(PDPT_SPAN));
const _: () = assert!(PAGE_TABLE_SIZE == (MAP_LIMIT / PDPT_SPAN + 2) * PAGE);
const _: () = assert!(SHIM_BASE + SHIM_SIZE == KERNEL_SETUP_BASE);
const _: () = assert!(KERNEL_SETUP_END <= KERNEL_BASE);
const _: () = assert!(KERNEL_BASE < INITRAMFS_BASE);
const _: () = assert!(SHIM_DATA + SHIM_DATA_SIZE <= SHIM_SIZE);
// An IGVM VP context indexes processors in 16 bits.
const _: () = assert!(MAX_VCPUS <= u16::MAX as u32);
// The park stub is a handful of instructions; it must not run into the template.
const _: () = assert!(SHIM_AP_PARK + 64 <= SHIM_MADT);
const _: () = assert!(SHIM_MADT + MADT_HEADER_LEN <= SHIM_DATA);
// A TD fetches its first instruction from the top of the 32-bit address space.
const _: () = assert!(RESET_ALIAS + PAGE == 0x1_0000_0000);

const _: () = assert!(RSDP_LEN <= ACPI_XSDT);
const _: () = assert!(ACPI_XSDT + XSDT_LEN <= ACPI_FADT);
const _: () = assert!(ACPI_FADT + FADT_LEN <= ACPI_DSDT);
const _: () = assert!(ACPI_DSDT + DSDT_LEN <= ACPI_MADT);
// The MADT Local APIC structure states an 8-bit APIC id, and 0xff is the xAPIC
// broadcast: a larger count would number two processors the same.
pub const MAX_VCPUS: u32 = 255;
// The last id a shim writes is one below the count, and 0xff is the broadcast.
const _: () = assert!(MAX_VCPUS > 0 && MAX_VCPUS - 1 < 0xff);
// One Local APIC entry per processor plus the wakeup structure, all inside the page.
const _: () = assert!(
    ACPI_MADT + MADT_HEADER_LEN + MAX_VCPUS as u64 * MADT_LAPIC_LEN + MADT_WAKEUP_LEN <= PAGE
);

// SEV_FEATURES, which QEMU forwards to KVM_SEV_INIT2: SNPActive only, no DebugSwap.
pub const SNP_SEV_FEATURES: u64 = 1;

// ABI 1.51 minimum with DEBUG and MIGRATE_MA clear; KVM rejects a policy without SMT.
const POLICY_ABI_MINOR: u64 = 51;
const POLICY_ABI_MAJOR: u64 = 1 << 8;
const POLICY_SMT: u64 = 1 << 16;
const POLICY_RESERVED_ONE: u64 = 1 << 17;
pub const SNP_GUEST_POLICY: u64 =
    POLICY_ABI_MINOR | POLICY_ABI_MAJOR | POLICY_SMT | POLICY_RESERVED_ONE;

pub const DEFAULT_RAM: u64 = 0x4000_0000;
pub const DEFAULT_VCPUS: u32 = 4;
pub const DEFAULT_CMDLINE: &str = "panic=-1";
// The encrypted identity map is built around this bit; no code before Linux discovers it.
pub const DEFAULT_CBIT: u8 = 51;

// The measured page tables are four-level, so this is appended to every command line.
const REQUIRED_CMDLINE: &str = "no5lvl";

pub struct Params {
    /// Top of the guest-physical map: low RAM, the PCI aperture and high RAM.
    pub memory: u64,
    pub vcpus: u32,
    pub cmdline: String,
    pub cbit: u8,
    /// The q35 PCI aperture, absent from E820 so Linux assigns BARs out of it,
    /// and accepted by no shim.
    pub mmio: Vec<(u64, u64)>,
}

impl Params {
    /// The extents QEMU's memory map will describe for a guest this size, each
    /// with whether it is ordinary memory: everything below the aperture, and
    /// the rest above 4 GiB (hw/i386/pc.c). The shim reads this from the
    /// loader rather than being told, so this is only what the build expects
    /// the loader to say.
    pub fn extents(&self) -> Vec<(u64, u64, bool)> {
        if self.mmio.is_empty() {
            vec![(0, self.memory, true)]
        } else {
            vec![(0, Q35_LOWMEM, true), (FOUR_GIB, self.memory, true)]
        }
    }
}

impl Params {
    /// The TDX shim runs from the reset page, so the aperture stops short of it.
    pub fn tdx(ram: u64, vcpus: u32, cmdline: &str) -> Result<Self, String> {
        Self::new(ram, vcpus, cmdline, DEFAULT_CBIT, RESET_ALIAS)
    }

    /// The SNP map, which places nothing inside the aperture, so it runs to 4 GiB.
    pub fn snp(ram: u64, vcpus: u32, cbit: u8, cmdline: &str) -> Result<Self, String> {
        Self::new(ram, vcpus, cmdline, cbit, FOUR_GIB)
    }

    fn new(ram: u64, vcpus: u32, cmdline: &str, cbit: u8, hole_end: u64) -> Result<Self, String> {
        if !ram.is_multiple_of(PAGE) || ram <= INITRAMFS_BASE || ram > MAX_RAM {
            return Err(format!(
                "--ram must be page-aligned, larger than {INITRAMFS_BASE:#x} \
                 and at most {MAX_RAM:#x}"
            ));
        }
        if vcpus == 0 || vcpus > MAX_VCPUS {
            return Err(format!("--vcpus must be between 1 and {MAX_VCPUS}"));
        }
        if !(32..=63).contains(&cbit) {
            return Err("--cbit must name a bit in the physical address width".into());
        }
        let cmdline = match cmdline.trim() {
            "" => format!("{DEFAULT_CMDLINE} {REQUIRED_CMDLINE}"),
            c if c.split_whitespace().any(|w| w == REQUIRED_CMDLINE) => c.to_string(),
            c => format!("{c} {REQUIRED_CMDLINE}"),
        };
        if cmdline.bytes().any(|b| b == 0 || !b.is_ascii()) {
            return Err("--cmdline must be printable ASCII".into());
        }
        // A split guest restacks above 4 GiB, so the map reaches past the RAM it has.
        let split = ram >= Q35_SPLIT;
        let memory = if split {
            FOUR_GIB + ram - Q35_LOWMEM
        } else {
            ram
        };
        let mmio: Vec<(u64, u64)> = split
            .then_some((Q35_LOWMEM, hole_end - Q35_LOWMEM))
            .into_iter()
            .collect();
        Ok(Params {
            memory,
            vcpus,
            cmdline,
            cbit,
            mmio,
        })
    }
}

pub fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

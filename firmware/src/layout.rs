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
    // The two pages the loader fills, both unmeasured: the
    // processor count, and the map of the machine the guest was given.
    PARAM_PAGE = 0x000e_1000;
    PARAM_MAP_PAGE = 0x000e_2000;
    MAILBOX = 0x000f_0000;
    SNP_CPUID = 0x000f_0000;
    SNP_SECRETS = 0x000f_1000;
    SNP_CC_BLOB = 0x000f_2000;
    PAGE_TABLES = 0x0010_0000;
    // One PML4 page and the four PDPT pages of 1-GiB pages that cover MAP_LIMIT.
    PAGE_TABLE_SIZE = 5 * PAGE;
    BSP_STACK = 0x0010_7000;
    BSP_STACK_SIZE = 0x0001_0000;
    BSP_STACK_TOP = BSP_STACK + BSP_STACK_SIZE;
    // The memory shapes this image runs in: for each, the loader's map it
    // accepts and the E820 and EFI tables it hands Linux (see SHAPE_* below).
    SHAPES_PAGE = 0x0011_7000;
    SHAPES_SIZE = 2 * PAGE;
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

    ACPI_SCI_IRQ = 9;
    Q35_PIT_GSI = 2;
    IOAPIC_ADDRESS = 0xfec0_0000;

    // The EFI tables both shims hand Linux so that it accepts most of guest RAM
    // itself, as it allocates: Linux finds unaccepted memory only through an
    // EFI configuration table (drivers/firmware/efi/unaccepted_memory.c), so
    // the image states an EFI boot that has already exited, with no boot or
    // runtime services and that one table. One measured page holds the system
    // table, its configuration table, the vendor string, the memory map and,
    // in its last bytes, the unaccepted table's header; the bitmap that header
    // begins follows it in the image's zero pages, so it arrives zero.
    EFI_PAGE = 0x0015_0000;
    EFI_CONFIG_TABLE = 0x80;
    EFI_VENDOR = 0xa0;
    // The memory map: a descriptor the image measures for this page, then the
    // shape's own descriptors, one for each RAM entry of its E820 map. Once
    // efi_info names a map, Linux's decompressor picks the physical address it
    // randomizes the kernel to from that map alone, so it names the RAM.
    EFI_MEMMAP = 0xc0;
    EFI_MEMDESC_SIZE = 48;
    EFI_MEMMAP_MAX = (UNACCEPTED_TABLE - EFI_PAGE - EFI_MEMMAP) / EFI_MEMDESC_SIZE;
    EFI_CONVENTIONAL_MEMORY = 7;
    EFI_MEMORY_WB = 8;
    UNACCEPTED_TABLE = EFI_PAGE + PAGE - 24;
    UNACCEPTED_SIZE = UNACCEPTED_TABLE + 16;
    // One bit a 2-MiB unit of everything the identity map reaches.
    UNACCEPTED_BITMAP = EFI_PAGE + PAGE;
    UNACCEPTED_BITMAP_SIZE = MAP_LIMIT / UNACCEPTED_UNIT / 8;
    UNACCEPTED_UNIT = 0x20_0000;
    UNACCEPTED_UNIT_SHIFT = 21;
    // boot_params' efi_info, as in arch/x86/include/uapi/asm/bootparam.h, and
    // the field in it a shim writes once it knows how long the map is.
    BP_EFI_INFO = 0x1c0;
    BP_EFI_MEMMAP_SIZE = BP_EFI_INFO + 20;

    // The GHCB MSR protocol, which needs no shared page: the one request an SNP
    // shim makes, to terminate.
    GHCB_MSR = 0xc001_0130;

    // The fixed part of the MADT, measured inside the shim page that builds the rest.
    SHIM_MADT = 0x0000_0b80;
    // A TD fetches its first instruction from the last 16 bytes of this page.
    RESET_VECTOR = PAGE - 16;

    // The kernel's 64-bit entry, startup_64, 0x200 into the protected-mode
    // payload (Documentation/arch/x86/boot.rst).
    KERNEL_ENTRY = KERNEL_BASE + 0x200;

    // One shape: the loader's map, entry for entry, with one RAM entry whose
    // size is the host's to choose within bounds; the E820 table and the EFI
    // descriptors this image hands Linux for it, the variable entry's end left
    // to the shim, which is the last of each; and the RAM ranges whose units
    // Linux accepts.
    SHAPE_LEN = 0x800;
    // How many entries the loader's map has, and which of them is variable.
    SHAPE_ENTRIES = 0;
    SHAPE_VAR = 8;
    // The least and most the variable entry may end at, once rounded down to a unit.
    SHAPE_VAR_MIN = 16;
    SHAPE_VAR_MAX = 24;
    // The loader's map: first page, page count (ignored for the variable
    // entry) and IGVM type, a word each.
    SHAPE_MAP = 32;
    SHAPE_MAP_ENTRY_LEN = 24;
    SHAPE_MAP_MAX = 4;
    SHAPE_E820_COUNT = 128;
    SHAPE_EFI_COUNT = 144;
    // RAM ranges as pairs, an end of zero meaning the top of RAM.
    SHAPE_RAM_COUNT = 160;
    SHAPE_RAM = 168;
    SHAPE_RAM_MAX = 8;
    SHAPE_E820 = 320;
    SHAPE_E820_MAX = 32;
    SHAPE_EFI = SHAPE_E820 + SHAPE_E820_MAX * E820_ENTRY_LEN;
    SHAPE_EFI_MAX = 16;

    ACPI_XSDT = 0x100;
    ACPI_FADT = 0x200;
    ACPI_DSDT = 0x400;
    ACPI_MADT = 0x500;
    RSDP_LEN = 36;
    XSDT_LEN = 52;
    FADT_LEN = 276;
    // The header followed by the PCI root bridge.
    DSDT_LEN = 59;
    MADT_HEADER_LEN = 44;
    MADT_IOAPIC_LEN = 12;
    MADT_OVERRIDE_LEN = 10;
    MADT_TEMPLATE_LEN = MADT_HEADER_LEN + MADT_IOAPIC_LEN + MADT_OVERRIDE_LEN;
    MADT_LAPIC_LEN = 8;
    MADT_WAKEUP_LEN = 16;
    // The MADT entry types the shims write, and the flag that says a processor is usable.
    MADT_LOCAL_APIC = 0;
    MADT_IOAPIC = 1;
    MADT_OVERRIDE = 2;
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

    // IGVM_VHS_MEMORY_MAP_ENTRY, of which the loader fills a page: QEMU writes
    // its E820 table there, sorted.
    MAP_ENTRY_LEN = 24;
    MAP_ENTRY_PAGES = 8;
    MAP_ENTRY_TYPE = 16;
    MAP_TYPE_MEMORY = 0;
    MAP_TYPE_RESERVED = 1;

    // The identity map reaches this far; past it a shim faults with no IDT installed.
    MAP_LIMIT = 2048 * GIB;
    // What one page-directory-pointer table of 1-GiB pages covers.
    PDPT_SPAN = 512 * GIB;
    FOUR_GIB = 4 * GIB;
    // q35 splits a guest this size or larger, opening a PCI aperture (hw/i386/pc_q35.c).
    Q35_SPLIT = 0xb000_0000;
    Q35_LOWMEM = 2 * GIB;
    // What KVM reserves for its identity map and TSS (target/i386/kvm/kvm.c).
    KVM_IDENTITY = 0xfeff_c000;
    KVM_IDENTITY_SIZE = 0x4000;
    // AMD's HyperTransport range, which QEMU reserves on an AMD guest and moves
    // RAM above when it would reach it (hw/i386/pc.c).
    AMD_HT_START = 0xfd_0000_0000;
    AMD_HT_END = 0x100_0000_0000;
    // The highest top of RAM a shape lets the loader's map reach.
    MAX_MEMORY = MAP_LIMIT;
}

pub const SHIM_LIMIT: usize = 256 * 1024;

const _: () = assert!(RESET_ALIAS < MAP_LIMIT);
// A shim reads the map as page numbers, so its bound is one too.
const _: () = assert!(MAX_MEMORY.is_multiple_of(PAGE));
// A shape's E820 table has to fit boot_params, and its map, plus the empty
// entry a shim reads after it, the loader's page.
const _: () = assert!(SHAPE_E820_MAX <= E820_MAX);
const _: () = assert!(BP_E820_TABLE + E820_MAX * E820_ENTRY_LEN <= PAGE);
const _: () = assert!((SHAPE_MAP_MAX + 1) * MAP_ENTRY_LEN <= PAGE);
// A shape record holds its fields, its map, its tables and nothing past them.
const _: () = assert!(SHAPE_MAP + SHAPE_MAP_MAX * SHAPE_MAP_ENTRY_LEN <= SHAPE_E820_COUNT);
const _: () = assert!(SHAPE_RAM + SHAPE_RAM_MAX * 16 <= SHAPE_E820);
const _: () = assert!(SHAPE_EFI + SHAPE_EFI_MAX * EFI_MEMDESC_SIZE <= SHAPE_LEN);
const _: () = assert!(SHAPES_SIZE.is_multiple_of(SHAPE_LEN));
// The measured descriptor and a shape's own fit the EFI page's map.
const _: () = assert!(SHAPE_EFI_MAX < EFI_MEMMAP_MAX);

// The low pages, in the order they are laid out.
const _: () = assert!(ACPI_BASE + PAGE == PARAM_PAGE && PARAM_PAGE + PAGE == PARAM_MAP_PAGE);
const _: () = assert!(PARAM_MAP_PAGE + PAGE <= MAILBOX);
const _: () = assert!(MAILBOX + PAGE <= PAGE_TABLES);
const _: () = assert!(SNP_CPUID + PAGE == SNP_SECRETS && SNP_SECRETS + PAGE == SNP_CC_BLOB);
const _: () = assert!(SNP_CC_BLOB + PAGE <= PAGE_TABLES);
const _: () = assert!(PAGE_TABLES + PAGE_TABLE_SIZE <= BSP_STACK);
const _: () = assert!(GDT_PTR + 10 <= BSP_STACK_TOP);
const _: () = assert!(BSP_STACK_TOP <= SHAPES_PAGE && SHAPES_PAGE + SHAPES_SIZE <= SHIM_BASE);
// The EFI page and the bitmap after it lie between the shim's pages and the
// kernel, the bitmap in a gap of the measured map that the image fills with
// zero pages: the header the shim sizes runs into it.
const _: () = assert!(KERNEL_SETUP_END <= EFI_PAGE && EFI_PAGE.is_multiple_of(PAGE));
// Both in the first unit, which arrives accepted for Linux's legacy scans.
const _: () = assert!(UNACCEPTED_BITMAP + UNACCEPTED_BITMAP_SIZE <= UNACCEPTED_UNIT);
const _: () = assert!(UNACCEPTED_UNIT == 1 << UNACCEPTED_UNIT_SHIFT);
// The bitmap has a bit for every unit the identity map reaches.
const _: () = assert!(UNACCEPTED_BITMAP_SIZE * 8 * UNACCEPTED_UNIT >= MAX_MEMORY);
const _: () = assert!(EFI_CONFIG_TABLE + 24 <= EFI_VENDOR && EFI_VENDOR + 16 <= EFI_MEMMAP);
// One PML4 page and one PDPT per PDPT_SPAN.
const _: () = assert!(MAP_LIMIT.is_multiple_of(PDPT_SPAN));
const _: () = assert!(PAGE_TABLE_SIZE == (MAP_LIMIT / PDPT_SPAN + 1) * PAGE);
// The variable entry is bounded in pages before a shim adds to it.
const _: () = assert!(MAX_MEMORY <= 1 << 52);
// RAM moved past HyperTransport starts at 1 TiB, which the identity map reaches.
const _: () = assert!(AMD_HT_END < MAP_LIMIT && KVM_IDENTITY + KVM_IDENTITY_SIZE <= RESET_ALIAS);
const _: () = assert!(SHIM_BASE + SHIM_SIZE == KERNEL_SETUP_BASE);
const _: () = assert!(KERNEL_SETUP_END <= KERNEL_BASE);
const _: () = assert!(KERNEL_BASE < INITRAMFS_BASE);
// An IGVM VP context indexes processors in 16 bits.
const _: () = assert!(MAX_VCPUS <= u16::MAX as u32);
// The park stub is a handful of instructions; it must not run into the template.
const _: () = assert!(SHIM_MADT + MADT_TEMPLATE_LEN <= RESET_VECTOR);
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
    ACPI_MADT + MADT_TEMPLATE_LEN + MAX_VCPUS as u64 * MADT_LAPIC_LEN + MADT_WAKEUP_LEN <= PAGE
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

pub const DEFAULT_CMDLINE: &str = "panic=-1";
// The encrypted identity map is built around this bit; no code before Linux discovers it.
pub const DEFAULT_CBIT: u8 = 51;

// The measured page tables are four-level, so this is appended to every command line.
const REQUIRED_CMDLINE: &str = "no5lvl";

/// What a build is asked for. None of it is the guest's size or processor
/// count: the shim takes the end of RAM from the loader's map, within the
/// shapes the image measures, and the processor count from its VP-count page.
pub struct Params {
    pub cmdline: String,
    pub cbit: u8,
}

impl Params {
    pub fn tdx(cmdline: &str) -> Result<Self, String> {
        Self::new(cmdline, DEFAULT_CBIT)
    }

    pub fn snp(cbit: u8, cmdline: &str) -> Result<Self, String> {
        Self::new(cmdline, cbit)
    }

    fn new(cmdline: &str, cbit: u8) -> Result<Self, String> {
        // Above 51 is not a physical address bit in four-level paging, so the
        // identity map would set a reserved bit or NX on every mapping.
        if !(32..=51).contains(&cbit) {
            return Err("--cbit must name a bit in the physical address width".into());
        }
        let cmdline = match cmdline.trim() {
            "" => format!("{DEFAULT_CMDLINE} {REQUIRED_CMDLINE}"),
            c if c.split_whitespace().any(|w| w == REQUIRED_CMDLINE) => c.to_string(),
            c => format!("{c} {REQUIRED_CMDLINE}"),
        };
        if cmdline.bytes().any(|b| !b.is_ascii_graphic() && b != b' ') {
            return Err("--cmdline must be printable ASCII".into());
        }
        // The EFI tables the image hands Linux have no runtime services: a
        // kernel told to use them anyway calls through a null table.
        if cmdline
            .split_whitespace()
            .any(|w| w.starts_with("efi=") && w.contains("runtime"))
        {
            return Err("--cmdline must not enable EFI runtime services".into());
        }
        Ok(Params { cmdline, cbit })
    }
}

pub fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

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

    ZERO_PAGE = 0x0000_7000;
    CMDLINE = 0x0002_0000;
    ACPI_BASE = 0x000e_0000;
    // The one page the loader fills and no shim accepts: the vCPU count, unmeasured.
    PARAM_PAGE = 0x000e_1000;
    MAILBOX = 0x000f_0000;
    SNP_CPUID = 0x000f_0000;
    SNP_SECRETS = 0x000f_1000;
    SNP_CC_BLOB = 0x000f_2000;
    PAGE_TABLES = 0x0010_0000;
    // The most either platform places: one PML4 page and one PDPT page of 1-GiB pages
    // (see MAP_LIMIT), plus on SNP a second PDPT page aliasing physical GiB 0 without
    // the C-bit (see SHARED_ALIAS). TDX places the first two only.
    PAGE_TABLE_SIZE = 3 * PAGE;
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

    // Physical GiB 0 seen again through PML4[1] with the C-bit clear: how the SNP
    // shim writes the one page it has made shared.
    SHARED_ALIAS = 0x80_0000_0000;

    // The fixed part of the MADT, measured inside the shim page that builds the rest.
    SHIM_MADT = 0x0000_0b80;
    // Where each shim finds its data block: the kernel entry point and the accept list.
    SHIM_DATA = 0x0000_0c00;
    // The block runs to the reset vector; nothing else lives in the page.
    SHIM_DATA_SIZE = RESET_VECTOR - SHIM_DATA;
    // A TD fetches its first instruction from the last 16 bytes of this page.
    RESET_VECTOR = PAGE - 16;

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
}

pub const SHIM_LIMIT: usize = 256 * 1024;

// The identity map reaches this far; past it a shim faults with no IDT installed.
pub const GIB: u64 = 0x4000_0000;
pub const MAP_LIMIT: u64 = 512 * GIB;
const FOUR_GIB: u64 = 4 * GIB;

// q35 splits a guest this size or larger, opening a PCI aperture (hw/i386/pc_q35.c).
const Q35_SPLIT: u64 = 0xb000_0000;
const Q35_LOWMEM: u64 = 2 * GIB;
// A split guest's map reaches 4 GiB plus the RAM that did not fit below the aperture.
pub const MAX_RAM: u64 = MAP_LIMIT - FOUR_GIB + Q35_LOWMEM;
const _: () = assert!(RESET_ALIAS < MAP_LIMIT);

// A shim accepts the gaps between these regions, so they tile in the order it skips them.
const _: () = assert!(ACPI_BASE + PAGE == PARAM_PAGE && PARAM_PAGE + PAGE <= MAILBOX);
const _: () = assert!(MAILBOX + PAGE <= PAGE_TABLES);
const _: () = assert!(SNP_CPUID + PAGE == SNP_SECRETS && SNP_SECRETS + PAGE == SNP_CC_BLOB);
const _: () = assert!(SNP_CC_BLOB + PAGE <= PAGE_TABLES);
const _: () = assert!(PAGE_TABLES + PAGE_TABLE_SIZE <= BSP_STACK);
const _: () = assert!(GDT_PTR + 10 <= BSP_STACK_TOP);
const _: () = assert!(BSP_STACK_TOP <= SNP_GHCB && SNP_GHCB + PAGE <= SHIM_BASE);
const _: () = assert!(SHARED_ALIAS == MAP_LIMIT);
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
// One Local APIC entry per vCPU plus the wakeup structure, all inside the page.
pub const MAX_VCPUS: u32 =
    ((PAGE - ACPI_MADT - MADT_HEADER_LEN - MADT_WAKEUP_LEN) / MADT_LAPIC_LEN) as u32;

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

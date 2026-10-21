use crate::mrtd;
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_TDX_PLATFORM_VERSION,
    IGVM_VHS_PARAMETER, IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use tinfoil_firmware::{
    boot::{self, Fill, Placed},
    io_error,
    layout::*,
};

// One compatibility mask bit: this file describes one platform.
pub const COMPAT: u32 = 1;
// Two parameter areas, one page each: the processor count in one and the
// loader's memory map in the other. They do not share a page because QEMU
// writes the memory map at the start of its area whatever byte offset the file
// states (backends/igvm.c), which would land on anything placed before it.
pub const PARAM_AREA: u32 = 0;
pub const PARAM_MAP_AREA: u32 = 1;
pub const PARAM_OFFSET: u32 = 0;

/// The page each area is inserted at. An area with another index, or one
/// inserted anywhere else, is not the file this digest describes.
pub fn param_gpa(index: u32) -> Option<u64> {
    match index {
        PARAM_AREA => Some(PARAM_PAGE),
        PARAM_MAP_AREA => Some(PARAM_MAP_PAGE),
        _ => None,
    }
}

/// Both unmeasured pages, in the order a loader imports them.
pub const PARAM_PAGES: [u64; 2] = [PARAM_PAGE, PARAM_MAP_PAGE];

/// A page a loader imports at `gpa`: its contents when the launch digest
/// covers them, and nothing when the loader is the one that fills the page.
#[derive(PartialEq)]
pub struct Page {
    pub gpa: u64,
    pub data: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct Component {
    address: String,
    size: usize,
    sha256: String,
}
// What a verifier should expect the report to say for this image: the digest,
// and the launch values this build chose. A value the host passes in is stated
// here when this build picked it, and left out when only the machine knows it.
pub type ReportFields = BTreeMap<&'static str, String>;

pub fn zeros(bytes: usize) -> String {
    "00".repeat(bytes)
}

// MRCONFIGID and HOST_DATA bind a deployment without entering the digest.
pub fn config_field(hash: Option<&str>, bytes: usize) -> Result<String, String> {
    match hash {
        None => Ok(zeros(bytes)),
        Some(h) => {
            let h = h.trim().trim_start_matches("0x").to_ascii_lowercase();
            if h.len() != bytes * 2 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("--config-hash must be {bytes} hex-encoded bytes"));
            }
            Ok(h)
        }
    }
}

// The guest takes SHA-256(config) from MRCONFIGID's first 32 bytes and refuses
// a nonzero tail, so refuse one here too: an image built with a tail the guest
// will not accept stops a guest that has no console to say why.
fn mrconfigid_field(hash: Option<&str>) -> Result<String, String> {
    const MRCONFIGID_BYTES: usize = 48;
    const HASH_BYTES: usize = 32;
    let field = config_field(hash, MRCONFIGID_BYTES)?;
    let tail = &field[HASH_BYTES * 2..];
    if tail.bytes().any(|b| b != b'0') {
        return Err(format!(
            "--config-hash pads the config hash with {tail}, not 16 zero bytes"
        ));
    }
    Ok(field)
}

#[derive(Serialize)]
struct Manifest {
    format_version: u32,
    platform: &'static str,
    memory_bytes: u64,
    vcpus: u32,
    command_line: String,
    mmio_holes: Vec<String>,
    kernel_entry: String,
    expected_mrtd: String,
    shim_owned_bytes: usize,
    launch: ReportFields,
    components: BTreeMap<&'static str, Component>,
}

/// The named regions of the map, each hashed where the map places it.
pub fn components(placed: &[Placed]) -> BTreeMap<&'static str, Component> {
    placed
        .iter()
        .filter(|p| !p.name.is_empty())
        .map(|p| (p.name, component(p.base, p.data())))
        .collect()
}

/// Serialize the Intel TDX launch state and publish what it measures.
pub fn build(
    kernel_path: &Path,
    initramfs_path: &Path,
    output: &Path,
    params: &Params,
    config_hash: Option<&str>,
) -> Result<(), String> {
    let mrconfigid = mrconfigid_field(config_hash)?;
    let launch = tinfoil_firmware::tdx(kernel_path, initramfs_path, params)?;

    let pages = launch_pages(&launch.placed)?;
    let file = igvm(&pages)?;
    // Read the file back the way a loader will, before publishing a digest for it.
    if igvm_pages(&file)? != pages {
        return Err("emitted IGVM file does not describe the measured pages".into());
    }
    let expected_mrtd = mrtd::calculate(&pages);
    fs::write(output, &file).map_err(io_error("write IGVM"))?;

    let manifest = Manifest {
        format_version: 3,
        platform: "tdx",
        memory_bytes: params.memory,
        vcpus: params.vcpus,
        command_line: params.cmdline.clone(),
        mmio_holes: mmio_holes(params),
        kernel_entry: format!("0x{:08x}", launch.entry),
        expected_mrtd: hex::encode(expected_mrtd),
        shim_owned_bytes: launch.shim_owned,
        launch: tdx_launch(&expected_mrtd, mrconfigid),
        components: components(&launch.placed),
    };
    write_manifest(output, &manifest)
}

pub fn mmio_holes(params: &Params) -> Vec<String> {
    params
        .mmio
        .iter()
        .map(|(base, size)| format!("0x{base:08x}:0x{size:x}"))
        .collect()
}

pub fn write_manifest<T: Serialize>(output: &Path, manifest: &T) -> Result<(), String> {
    let mut json = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
    json.push(b'\n');
    fs::write(format!("{}.manifest.json", output.display()), json)
        .map_err(io_error("write manifest"))
}

/// The order a loader imports these in, which is the order every digest folds
/// them in. The pages the loader fills come first: QEMU batches page data and
/// flushes the batch only at the next page directive, so a parameter insert
/// lands ahead of the pages it interrupts (backends/igvm.c).
pub fn launch_pages(placed: &[Placed]) -> Result<Vec<Page>, String> {
    let mut out = Vec::new();
    for region in placed {
        if matches!(region.fill, Fill::Parameters) {
            out.push(Page {
                gpa: region.base,
                data: None,
            });
        }
    }
    for region in placed {
        match &region.fill {
            Fill::Measured(data) => {
                out.extend(boot::pages(region.base, data).map(|(gpa, data)| Page {
                    gpa,
                    data: Some(data),
                }))
            }
            Fill::Parameters | Fill::Mmio(_) => {}
            Fill::Host => {
                return Err(format!(
                    "{:#x} is placed but has no measured contents",
                    region.base
                ))
            }
        }
    }
    Ok(out)
}

/// The area QEMU deposits one parameter in, and its insertion at `gpa`. The
/// contents are unmeasured and untrusted; the address, the size and the kind
/// of parameter are not.
pub fn parameter_directives(gpa: u64) -> Result<Vec<IgvmDirectiveHeader>, String> {
    let index = match gpa {
        PARAM_PAGE => PARAM_AREA,
        PARAM_MAP_PAGE => PARAM_MAP_AREA,
        _ => {
            return Err(format!(
                "{gpa:#x} is not a parameter page this image asks for"
            ))
        }
    };
    let parameter = IGVM_VHS_PARAMETER {
        parameter_area_index: index,
        byte_offset: PARAM_OFFSET,
    };
    Ok(vec![
        IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: PAGE,
            parameter_area_index: index,
            initial_data: Vec::new(),
        },
        if index == PARAM_AREA {
            IgvmDirectiveHeader::VpCount(parameter)
        } else {
            IgvmDirectiveHeader::MemoryMap(parameter)
        },
        IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
            gpa,
            compatibility_mask: COMPAT,
            parameter_area_index: index,
        }),
    ])
}

/// A page a loader imports at `gpa`: 4 KiB, private and measured, which is flags of zero.
pub fn page_directive(gpa: u64, data_type: IgvmPageDataType, data: Vec<u8>) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::PageData {
        gpa,
        compatibility_mask: COMPAT,
        flags: IgvmPageDataFlags::new(),
        data_type,
        data,
    }
}

fn igvm(pages: &[Page]) -> Result<Vec<u8>, String> {
    let platform = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: COMPAT,
        highest_vtl: 0,
        platform_type: IgvmPlatformType::TDX,
        platform_version: IGVM_TDX_PLATFORM_VERSION,
        // Nothing is loaded shared and the guest reads its own GPAW, so no boundary is stated.
        shared_gpa_boundary: 0,
    });
    let mut directives = Vec::new();
    for p in pages {
        match &p.data {
            Some(data) => directives.push(page_directive(
                p.gpa,
                IgvmPageDataType::NORMAL,
                data.clone(),
            )),
            None => directives.extend(parameter_directives(p.gpa)?),
        }
    }
    let file = IgvmFile::new(IgvmRevision::V1, vec![platform], vec![], directives)
        .map_err(|e| format!("construct TDX IGVM: {e}"))?;
    let mut out = Vec::new();
    file.serialize(&mut out)
        .map_err(|e| format!("serialize TDX IGVM: {e}"))?;
    Ok(out)
}

/// Reads an image back the way a loader does, refusing any directive that is
/// neither a measured page nor the one parameter area.
fn igvm_pages(file: &[u8]) -> Result<Vec<Page>, String> {
    let mut out = Vec::new();
    for directive in IgvmFile::new_from_binary(file, None)
        .map_err(|e| format!("read back TDX IGVM: {e}"))?
        .directives()
    {
        match directive {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
                flags,
                data_type,
                data,
            } if *compatibility_mask == COMPAT
                && *data_type == IgvmPageDataType::NORMAL
                && !flags.is_2mb_page()
                && !flags.unmeasured()
                && !flags.shared()
                && data.len() == PAGE as usize =>
            {
                out.push(Page {
                    gpa: *gpa,
                    data: Some(data.clone()),
                })
            }
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data,
            } if *number_of_bytes == PAGE
                && param_gpa(*parameter_area_index).is_some()
                && initial_data.is_empty() => {}
            IgvmDirectiveHeader::VpCount(p)
                if p.parameter_area_index == PARAM_AREA && p.byte_offset == PARAM_OFFSET => {}
            IgvmDirectiveHeader::MemoryMap(p)
                if p.parameter_area_index == PARAM_MAP_AREA && p.byte_offset == PARAM_OFFSET => {}
            IgvmDirectiveHeader::ParameterInsert(p)
                if param_gpa(p.parameter_area_index) == Some(p.gpa)
                    && p.compatibility_mask == COMPAT =>
            {
                if out.iter().any(|p| p.data.is_some()) {
                    return Err("TDX IGVM inserts a parameter area after page data".into());
                }
                out.push(Page {
                    gpa: p.gpa,
                    data: None,
                });
            }
            _ => return Err("TDX IGVM carries a directive this image never emits".to_string()),
        }
    }
    // Every unmeasured page this image asks for, imported exactly once and
    // before anything the digest covers.
    let parameters: Vec<u64> = out
        .iter()
        .filter(|p| p.data.is_none())
        .map(|p| p.gpa)
        .collect();
    if parameters != PARAM_PAGES {
        return Err(format!(
            "TDX IGVM inserts parameter areas at {parameters:#x?}, expected {PARAM_PAGES:#x?}"
        ));
    }
    Ok(out)
}

// What a TD launched from this image reports. ATTRIBUTES, XFAM, the owner
// registers, SERVTD_HASH and TEE_TCB_SVN are the host's to choose at
// TDH.MNG.INIT, so they belong to the verifier's platform policy, not here.
fn tdx_launch(mrtd: &[u8; 48], mrconfigid: String) -> ReportFields {
    let mut r = ReportFields::new();
    r.insert("mrtd", hex::encode(mrtd));
    r.insert("mrconfigid", mrconfigid);
    // This image extends no RTMR, so each register is still at its reset value.
    for name in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
        r.insert(name, zeros(48));
    }
    r
}

pub fn component(address: u64, data: &[u8]) -> Component {
    Component {
        address: format!("0x{address:08x}"),
        size: data.len(),
        sha256: hex::encode(Sha256::digest(data)),
    }
}

/// Recompute the Intel TDX launch digest from a serialized image.
pub fn measure_tdx(file: &[u8]) -> Result<[u8; 48], String> {
    let pages = igvm_pages(file)?;
    // MEM.PAGE.ADD folds pages in file order, so a file that states a page
    // twice, or whose measured pages descend, measures to a value no hardware
    // will report.
    let mut stated: Vec<u64> = pages.iter().map(|p| p.gpa).collect();
    stated.sort_unstable();
    if stated.windows(2).any(|w| w[0] == w[1]) {
        return Err("TDX image states a page more than once".into());
    }
    let measured: Vec<u64> = pages
        .iter()
        .filter(|p| p.data.is_some())
        .map(|p| p.gpa)
        .collect();
    for pair in measured.windows(2) {
        if pair[0] + PAGE > pair[1] {
            return Err(format!(
                "TDX pages are not in ascending order, or overlap, at {:#x}",
                pair[1]
            ));
        }
    }
    Ok(crate::mrtd::calculate(&pages))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use tempfile::tempdir;
    use tinfoil_firmware::boot::{Shape, ABSENT, RAM, RESERVED};

    pub fn params() -> Params {
        Params::tdx(DEFAULT_RAM, DEFAULT_VCPUS, "").unwrap()
    }

    /// A bzImage-shaped stub: enough of the setup header for the builder to accept it.
    pub fn test_kernel() -> Vec<u8> {
        let mut kernel = vec![0u8; 8192];
        kernel[0x1f1] = 4;
        kernel[0x1fe..0x200].copy_from_slice(&0xaa55u16.to_le_bytes());
        kernel[0x202..0x206].copy_from_slice(b"HdrS");
        kernel[0x206..0x208].copy_from_slice(&0x020cu16.to_le_bytes());
        kernel[0x211] = 1;
        kernel[0x230..0x234].copy_from_slice(&0x20_0000u32.to_le_bytes());
        kernel[0x234] = 1;
        kernel[0x236] = 1;
        kernel[0x238..0x23c].copy_from_slice(&0x800u32.to_le_bytes());
        kernel[0x260..0x264].copy_from_slice(&0x20_0000u32.to_le_bytes());
        kernel
    }

    #[test]
    fn measure_reproduces_what_build_published() {
        let dir = tempdir().unwrap();
        let (k, i, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        build(
            &k,
            &i,
            &out,
            &Params::tdx(DEFAULT_RAM, 1, "").unwrap(),
            None,
        )
        .unwrap();

        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(out.with_extension("igvm.manifest.json")).unwrap())
                .unwrap();
        assert_eq!(
            manifest["expected_mrtd"].as_str().unwrap(),
            hex::encode(measure_tdx(&fs::read(&out).unwrap()).unwrap())
        );
    }

    #[test]
    fn config_hash_is_pinned_or_zero() {
        assert_eq!(config_field(None, 32), Ok(zeros(32)));
        assert_eq!(
            config_field(Some(&"AB".repeat(32)), 32),
            Ok("ab".repeat(32))
        );
        assert!(config_field(Some("abcd"), 32).is_err());
        assert!(config_field(Some(&"zz".repeat(32)), 32).is_err());
    }

    #[test]
    fn mrconfigid_carries_the_hash_and_nothing_else() {
        assert_eq!(mrconfigid_field(None), Ok(zeros(48)));
        let padded = "ab".repeat(32) + &zeros(16);
        assert_eq!(mrconfigid_field(Some(&padded)), Ok(padded.clone()));
        // A tail the guest refuses must not reach an image or a manifest.
        assert!(mrconfigid_field(Some(&("ab".repeat(32) + &zeros(15) + "01"))).is_err());
        assert!(mrconfigid_field(Some(&("ab".repeat(32) + "01" + &zeros(15)))).is_err());
        assert!(mrconfigid_field(Some(&"ab".repeat(32))).is_err());
    }

    #[test]
    fn required_cmdline_is_appended_whatever_the_operator_asks_for() {
        assert_eq!(params().cmdline, "panic=-1 no5lvl");
        let p = Params::tdx(DEFAULT_RAM, 1, "quiet").unwrap();
        assert_eq!(p.cmdline, "quiet no5lvl");
        let p = Params::tdx(DEFAULT_RAM, 1, "no5lvl x").unwrap();
        assert_eq!(p.cmdline, "no5lvl x");
        assert!(Params::tdx(DEFAULT_RAM, 0, "").is_err());
        assert!(Params::tdx(0x1000, 1, "").is_err());
        assert!(Params::tdx(DEFAULT_RAM, MAX_VCPUS + 1, "").is_err());
    }

    /// Every input the measurement is claimed to cover must move it. An input
    /// that can change while the digest stays put has silently fallen outside
    /// the measurement, and every check downstream still passes -- an image
    /// that no longer commits to its own kernel still verifies. That is the
    /// failure this whole design exists to make impossible, and it is invisible
    /// unless something asserts it.
    #[test]
    fn changing_any_measured_input_moves_the_measurement() {
        let dir = tempdir().unwrap();
        let kernel = dir.path().join("bzImage");
        let initramfs = dir.path().join("initrd");
        fs::write(&kernel, test_kernel()).unwrap();
        fs::write(&initramfs, vec![7u8; 100_000]).unwrap();
        let cmdline = "root=/dev/mapper/root roothash=aa11";

        let mrtd = |k: &Path, i: &Path, c: &str, vcpus: u32| -> String {
            let out = dir.path().join("out.igvm");
            let params = Params::tdx(DEFAULT_RAM, vcpus, c).unwrap();
            build(k, i, &out, &params, None).unwrap();
            let manifest = fs::read(format!("{}.manifest.json", out.display())).unwrap();
            let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
            manifest["expected_mrtd"].as_str().unwrap().to_owned()
        };

        let base = mrtd(&kernel, &initramfs, cmdline, DEFAULT_VCPUS);
        // A baseline that moved on its own would make every assertion below
        // pass for the wrong reason.
        assert_eq!(base, mrtd(&kernel, &initramfs, cmdline, DEFAULT_VCPUS));

        let other = dir.path().join("bzImage.other");
        let mut bytes = test_kernel();
        bytes[4096] ^= 1;
        fs::write(&other, bytes).unwrap();
        let moved = mrtd(&other, &initramfs, cmdline, DEFAULT_VCPUS);
        assert_ne!(
            base, moved,
            "one byte of the kernel left the measurement alone"
        );

        let other = dir.path().join("initrd.other");
        let mut bytes = vec![7u8; 100_000];
        bytes[1000] ^= 1;
        fs::write(&other, bytes).unwrap();
        let moved = mrtd(&kernel, &other, cmdline, DEFAULT_VCPUS);
        assert_ne!(
            base, moved,
            "one byte of the initramfs left the measurement alone"
        );

        // One hex digit of the root hash. The command line is what binds the
        // image to a root filesystem, so this is the mutation that matters most.
        let moved = mrtd(
            &kernel,
            &initramfs,
            "root=/dev/mapper/root roothash=ab11",
            DEFAULT_VCPUS,
        );
        assert_ne!(base, moved, "the command line left the measurement alone");
    }

    /// The processor count and the guest's RAM are the two launch inputs the
    /// digest no longer covers: the tables that depended on them are written by
    /// the shim, out of parameters the loader fills after the measurement is
    /// closed. Holding the rest of the image still, MRTD must not move with
    /// either -- that is the whole point of taking those tables out of the
    /// measured pages.
    #[test]
    fn the_machine_size_leaves_the_measurement_alone() {
        let mrtd = |ram, vcpus| {
            let params = Params::tdx(ram, vcpus, "").unwrap();
            built(&params).1["expected_mrtd"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let base = mrtd(DEFAULT_RAM, 2);
        for vcpus in [4, 8, MAX_VCPUS] {
            assert_eq!(
                base,
                mrtd(DEFAULT_RAM, vcpus),
                "{vcpus} processors moved MRTD"
            );
        }
        for ram in [
            DEFAULT_RAM + PAGE,
            2 * GIB,
            8 * GIB,
            64 * GIB,
            1024 * GIB,
            MAX_RAM,
        ] {
            assert_eq!(base, mrtd(ram, 2), "{ram:#x} of RAM moved MRTD");
        }
    }

    /// The image is byte-identical too, not merely equally measured: nothing a
    /// TDX file states depends on the machine it is launched on.
    #[test]
    fn a_tdx_image_is_the_same_file_whatever_machine_it_is_built_for() {
        let one = built(&Params::tdx(DEFAULT_RAM, 2, "").unwrap()).0;
        for (ram, vcpus) in [(8 * GIB, 8u32), (MAX_RAM, MAX_VCPUS)] {
            assert_eq!(one, built(&Params::tdx(ram, vcpus, "").unwrap()).0);
        }
    }

    /// Builds from stub inputs and returns the IGVM file and the manifest beside it.
    pub fn built(params: &Params) -> (Vec<u8>, serde_json::Value) {
        let dir = tempdir().unwrap();
        let (kernel, initramfs, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&kernel, test_kernel()).unwrap();
        fs::write(&initramfs, vec![7u8; 100_000]).unwrap();
        build(&kernel, &initramfs, &out, params, None).unwrap();
        let manifest = fs::read(format!("{}.manifest.json", out.display())).unwrap();
        (
            fs::read(out).unwrap(),
            serde_json::from_slice(&manifest).unwrap(),
        )
    }

    fn reset_page(file: &[u8]) -> Vec<u8> {
        let last = igvm_pages(file).unwrap().pop().unwrap();
        assert_eq!(last.gpa, RESET_ALIAS);
        last.data.unwrap()
    }

    #[test]
    fn builds_a_byte_identical_loadable_igvm_file() {
        let one = built(&params()).0;
        assert_eq!(one, built(&params()).0);
        // Read back the way a loader does: whole measured pages in ascending order.
        let pages = igvm_pages(&one).unwrap();
        let measured: Vec<&Page> = pages.iter().filter(|p| p.data.is_some()).collect();
        assert!(measured.windows(2).all(|w| w[0].gpa + PAGE <= w[1].gpa));
        // The one page the loader fills is imported before any of them.
        let first = pages.first().unwrap();
        assert!(first.gpa == PARAM_PAGE && first.data.is_none());
        // The architectural reset instruction is the last 16 bytes of memory.
        assert_eq!(reset_page(&one)[PAGE as usize - 16], 0xe9);
    }

    /// Builds both platforms' launch state from stub inputs.
    fn launched(dir: &Path, ram: u64, snp: bool) -> (Params, tinfoil_firmware::Launch) {
        let (k, i) = (dir.join("bzImage"), dir.join("initrd"));
        if !k.exists() {
            fs::write(&k, test_kernel()).unwrap();
            fs::write(&i, vec![7u8; 100_000]).unwrap();
        }
        let params = if snp {
            Params::snp(ram, 1, DEFAULT_CBIT, "").unwrap()
        } else {
            Params::tdx(ram, 1, "").unwrap()
        };
        let launch = if snp {
            tinfoil_firmware::snp(&k, &i, &params)
        } else {
            tinfoil_firmware::tdx(&k, &i, &params)
        }
        .unwrap();
        (params, launch)
    }

    /// Guest sizes QEMU lays out every way it does: below the aperture, at
    /// both sides of it, and on AMD on both sides of HyperTransport.
    const SIZES: [u64; 10] = [
        0x2020_0000,
        DEFAULT_RAM,
        2 * GIB,
        Q35_SPLIT - PAGE,
        Q35_SPLIT,
        8 * GIB,
        64 * GIB,
        980 * GIB,
        1024 * GIB,
        1026 * GIB,
    ];
    const UNIT: u64 = 0x20_0000;
    const AMD_HOLE64: u64 = 32 * GIB;

    /// A loader's memory map: start page, page count and type, per entry.
    type Map = Vec<(u64, u64, u16)>;

    /// The memory map QEMU states for a q35 guest of `ram` as tinfoild launches
    /// one: its E820 table, sorted (hw/i386/pc.c, pc_q35.c, kvm.c). On AMD,
    /// with QEMU's default 64-bit PCI hole, high RAM moves past HyperTransport
    /// once that hole would reach it.
    fn qemu_map(ram: u64, amd: bool) -> Map {
        let (mem, res) = (MAP_TYPE_MEMORY as u16, MAP_TYPE_RESERVED as u16);
        let low = if ram >= Q35_SPLIT { Q35_LOWMEM } else { ram };
        let mut map = vec![(0, low, mem), (KVM_IDENTITY, KVM_IDENTITY_SIZE, res)];
        if amd {
            map.push((AMD_HT_START, AMD_HT_END - AMD_HT_START, res));
        }
        if ram > low {
            let high = ram - low;
            let start = match amd && align_up(FOUR_GIB + high, GIB) + AMD_HOLE64 > AMD_HT_START {
                true => AMD_HT_END,
                false => FOUR_GIB,
            };
            map.push((start, high, mem));
        }
        map.sort_unstable();
        map.iter()
            .map(|(lo, len, t)| (lo / PAGE, len / PAGE, *t))
            .collect()
    }

    /// An image's measured page at `base`.
    fn placed_page(launch: &tinfoil_firmware::Launch, base: u64) -> Vec<u8> {
        launch
            .placed
            .iter()
            .find(|p| p.base == base)
            .unwrap()
            .data()
            .to_vec()
    }

    /// The shim's data block, out of the page an image carries it in.
    fn data_block_of(launch: &tinfoil_firmware::Launch, snp: bool) -> Vec<u8> {
        let page = placed_page(launch, if snp { SHIM_BASE } else { RESET_ALIAS });
        page[SHIM_DATA as usize..(SHIM_DATA + SHIM_DATA_SIZE) as usize].to_vec()
    }

    /// A shim loaded with an image's own shapes page and data block.
    fn shim_for(launch: &tinfoil_firmware::Launch, snp: bool) -> tinfoil_firmware::shim::Shim {
        let shim = tinfoil_firmware::shim::shim();
        shim.image(
            &placed_page(launch, SHAPES_PAGE),
            &data_block_of(launch, snp),
        );
        shim
    }

    /// The units Linux is owed for a guest of `shape` whose RAM tops out at
    /// `top`: every whole one of its RAM at or past the bound, and no other.
    fn owed_units(shape: &Shape, top: u64, lazy: u64, placed: &[(u64, u64)]) -> Vec<u64> {
        shape
            .extents(top)
            .iter()
            .filter(|(_, _, ram)| *ram)
            .flat_map(|(lo, hi, _)| (lo.max(&lazy) / UNIT)..(hi / UNIT))
            .filter(|u| {
                !placed
                    .iter()
                    .any(|(lo, hi)| *lo < (u + 1) * UNIT && *hi > u * UNIT)
            })
            .collect()
    }

    /// The shim accepts the RAM below the lazy bound the image did not place,
    /// and nothing else: no page it loaded (accepting one again would replace
    /// it), no page past the bound (that is Linux's), and no gap.
    #[test]
    fn the_shim_accepts_exactly_the_ram_below_the_bound_it_did_not_place() {
        let dir = tempdir().unwrap();
        for snp in [false, true] {
            let (_, launch) = launched(dir.path(), 8 * GIB, snp);
            let block = data_block_of(&launch, snp);
            let word = |at: u64| u64::from_le_bytes(block[at as usize..][..8].try_into().unwrap());
            assert_eq!(word(SHIM_DATA_ENTRY), KERNEL_BASE + 0x200);
            assert_eq!(word(SHIM_DATA_SHAPES), launch.shapes.len() as u64);
            let mut listed = Vec::new();
            let mut at = SHIM_DATA_ACCEPT;
            while word(at + 8) != 0 {
                listed.push((word(at), word(at + 8)));
                at += 16;
            }
            assert_eq!(listed, launch.accept);
            let placed: Vec<(u64, u64)> = launch
                .spans
                .iter()
                .filter(|(lo, _, _)| *lo < launch.lazy)
                .map(|(lo, hi, _)| (*lo, *hi))
                .collect();
            let mut tiles: Vec<(u64, u64)> = listed
                .iter()
                .copied()
                .filter(|(lo, _)| *lo < launch.lazy)
                .chain(placed)
                .collect();
            tiles.sort_unstable();
            let mut at = 0;
            for (lo, hi) in tiles {
                assert_eq!(lo, at, "snp={snp}: {at:#x} is neither accepted nor placed");
                at = hi;
            }
            assert!(
                at >= launch.lazy,
                "snp={snp}: RAM below the bound is left out"
            );
            // Past the bound, only what the image leaves of the units it
            // places in.
            for (lo, hi) in listed.iter().filter(|(_, hi)| *hi > launch.lazy) {
                let unit = lo / UNIT * UNIT;
                assert!(
                    launch.spans.iter().any(|(s, e, kind)| *kind == RAM
                        && *s < (hi - 1) / UNIT * UNIT + UNIT
                        && *e > unit),
                    "snp={snp}: {lo:#x} past the bound shares no unit with the image"
                );
            }
        }
    }

    /// However long the initramfs, the unit after its last page is the shim's
    /// to accept and never Linux's: Linux frees the initramfs without the
    /// guard it keeps after memory it accepts itself, and
    /// load_unaligned_zeropad() reads past the last page of what it frees.
    #[test]
    fn the_unit_after_the_initramfs_is_accepted_however_long_it_is() {
        for len in [UNIT, 2 * UNIT - PAGE, 3 * UNIT + 1] {
            let dir = tempdir().unwrap();
            fs::write(dir.path().join("bzImage"), test_kernel()).unwrap();
            fs::write(dir.path().join("initrd"), vec![7u8; len as usize]).unwrap();
            for snp in [false, true] {
                let (_, launch) = launched(dir.path(), 8 * GIB, snp);
                let end = (INITRAMFS_BASE + len).div_ceil(PAGE) * PAGE;
                let guard = (end / UNIT * UNIT, end / UNIT * UNIT + UNIT);
                assert!(
                    launch
                        .accept
                        .iter()
                        .any(|(lo, hi)| *lo <= end && guard.1 <= *hi),
                    "len={len:#x}, snp={snp}: [{end:#x}, {:#x}) is not accepted",
                    guard.1
                );
                let shim = shim_for(&launch, snp);
                shim.loader_memory_map(&qemu_map(8 * GIB, snp));
                let got = shim
                    .boot_map(
                        &placed_page(&launch, EFI_PAGE),
                        &placed_page(&launch, ZERO_PAGE),
                    )
                    .unwrap();
                assert!(
                    !got.units.contains(&(guard.0 / UNIT)),
                    "len={len:#x}, snp={snp}: the guard unit is marked"
                );
                assert!(got.units.contains(&(guard.1 / UNIT)));
            }
        }
    }

    /// Every map QEMU states for these guests is one of the image's shapes, so
    /// no guest tinfoild launches is refused for the layout it was given.
    #[test]
    fn every_qemu_layout_is_a_shape() {
        let dir = tempdir().unwrap();
        for snp in [false, true] {
            let (_, launch) = launched(dir.path(), 8 * GIB, snp);
            let shim = shim_for(&launch, snp);
            for ram in SIZES {
                let map = qemu_map(ram, snp);
                shim.loader_memory_map(&map);
                let top = shim
                    .boot_map(
                        &placed_page(&launch, EFI_PAGE),
                        &placed_page(&launch, ZERO_PAGE),
                    )
                    .map(|b| b.top);
                let (lo, pages, _) = *map.iter().rfind(|e| e.2 == 0).unwrap();
                let end = (lo + pages) * PAGE / UNIT * UNIT;
                assert_eq!(top, Some(end), "{ram:#x}, snp={snp}: {map:x?}");
            }
        }
    }

    /// The shim's own assembly, run against an image's measured shapes page,
    /// data block, EFI page and zero page, for every shape it carries at both
    /// of its bounds and between them, an end off a unit boundary included.
    /// It has to hand Linux exactly the tables boot.rs specifies for that
    /// guest, accept exactly the image's fixed ranges, and leave Linux exactly
    /// the whole units of RAM past the bound: a unit marked and accepted both
    /// would be validated twice, which terminates the guest, and a unit marked
    /// past the RAM would send Linux to accept memory no one backed.
    #[test]
    fn the_shim_builds_the_tables_each_shape_specifies() {
        let dir = tempdir().unwrap();
        for snp in [false, true] {
            let (_, launch) = launched(dir.path(), 8 * GIB, snp);
            let shim = shim_for(&launch, snp);
            let (efi, zero) = (
                placed_page(&launch, EFI_PAGE),
                placed_page(&launch, ZERO_PAGE),
            );
            for shape in &launch.shapes {
                let mid = (shape.min_end + (shape.max_end - shape.min_end) / 2) / UNIT * UNIT;
                for end in [
                    shape.min_end,
                    shape.min_end + UNIT + 3 * PAGE,
                    mid,
                    shape.max_end,
                    shape.max_end + UNIT - PAGE,
                ] {
                    let what = format!("snp={snp}, end {end:#x} of {shape:?}");
                    let top = end / UNIT * UNIT;
                    let got = shim.loader_shape(shape, end).boot_map(&efi, &zero);
                    let got = got.unwrap_or_else(|| panic!("{what}: refused"));
                    assert_eq!(got.top, top, "{what}: top");
                    let e820 = shape.e820(&launch.spans, top);
                    assert_eq!(got.e820, e820, "{what}: E820");
                    for pair in e820.windows(2) {
                        assert!(pair[0].0 + pair[0].1 <= pair[1].0, "{what}: E820 overlaps");
                    }
                    let ram: Vec<(u32, u64, u64, u64)> = e820
                        .iter()
                        .filter(|e| e.2 == RAM)
                        .map(|(base, len, _)| {
                            (
                                EFI_CONVENTIONAL_MEMORY as u32,
                                *base,
                                len / PAGE,
                                EFI_MEMORY_WB,
                            )
                        })
                        .collect();
                    assert_eq!(
                        got.efi[0],
                        (2, EFI_PAGE, 1, EFI_MEMORY_WB),
                        "{what}: measured"
                    );
                    assert_eq!(got.efi[1..], ram[..], "{what}: the RAM the EFI map lists");
                    assert_eq!(
                        got.efi_size as usize,
                        got.efi.len() * EFI_MEMDESC_SIZE as usize
                    );
                    assert_eq!(got.accepted, launch.accept, "{what}: accepted");
                    // Every page the image places arrives accepted, and Linux
                    // accepting one again terminates the guest.
                    let placed: Vec<(u64, u64)> = launch
                        .placed
                        .iter()
                        .filter(|p| p.e820 != ABSENT)
                        .map(|p| (p.base, p.base + p.span()))
                        .collect();
                    assert!(
                        got.units.iter().all(|u| !placed
                            .iter()
                            .any(|(lo, hi)| *lo < (u + 1) * UNIT && *hi > u * UNIT)),
                        "{what}: a unit the image placed a page in is marked"
                    );
                    assert_eq!(
                        got.units,
                        owed_units(shape, top, launch.lazy, &placed),
                        "{what}: units"
                    );
                    // Each page of RAM the guest is told of arrives accepted,
                    // is accepted by the shim, or lies in a unit Linux
                    // accepts: exactly one of them. A page that is none is
                    // touched unaccepted; one that is two is accepted twice.
                    let mut owners: Vec<(u64, u64)> = placed
                        .iter()
                        .copied()
                        .chain(got.accepted.iter().copied())
                        .chain(got.units.iter().map(|u| (u * UNIT, (u + 1) * UNIT)))
                        .collect();
                    owners.sort_unstable();
                    for w in owners.windows(2) {
                        assert!(w[0].1 <= w[1].0, "{what}: {:#x} is accepted twice", w[1].0);
                    }
                    for (base, len, _) in e820.iter().filter(|e| e.2 == RAM) {
                        let mut at = *base;
                        for (lo, hi) in &owners {
                            if *hi <= at || *lo >= base + len {
                                continue;
                            }
                            assert!(*lo <= at, "{what}: {at:#x} is RAM no one accepts");
                            at = at.max(*hi);
                        }
                        assert!(at >= base + len, "{what}: {at:#x} is RAM no one accepts");
                    }
                    assert!(got.units.iter().all(|u| (u + 1) * UNIT <= top));
                    assert_eq!(got.unaccepted_size, top.div_ceil(UNIT).div_ceil(8));
                    // Nothing the image placed is free memory, bar the RAM it
                    // loaded the kernel and initramfs into.
                    for (_, base, pages, _) in &got.efi[1..] {
                        let end = base + pages * PAGE;
                        for p in launch.placed.iter().filter(|p| p.e820 != ABSENT) {
                            let overlaps = p.base < end && *base < p.base + p.span();
                            assert!(!overlaps || p.e820 == RAM, "{what}: {:#x} is free", p.base);
                        }
                    }
                }
            }
        }
    }

    /// A map that is not exactly one of the image's shapes is refused, not
    /// fitted: the only thing a loader decides is where one entry ends, within
    /// bounds the image set.
    #[test]
    fn a_map_that_is_no_shape_is_refused() {
        let dir = tempdir().unwrap();
        for snp in [false, true] {
            let (_, launch) = launched(dir.path(), 8 * GIB, snp);
            let shim = shim_for(&launch, snp);
            let (efi, zero) = (
                placed_page(&launch, EFI_PAGE),
                placed_page(&launch, ZERO_PAGE),
            );
            let good = qemu_map(8 * GIB, snp);
            shim.loader_memory_map(&good);
            assert!(
                shim.boot_map(&efi, &zero).is_some(),
                "snp={snp}: a good map is refused"
            );
            let page = |gpa: u64| gpa / PAGE;
            let (mem, res) = (MAP_TYPE_MEMORY as u16, MAP_TYPE_RESERVED as u16);
            let ht = (page(AMD_HT_START), page(AMD_HT_END - AMD_HT_START), res);
            let edit = |f: &dyn Fn(&mut Map)| {
                let mut m = good.clone();
                f(&mut m);
                m
            };
            let small = launch.shapes[0].min_end;
            let mut cases: Vec<(&str, Map)> = vec![
                ("an empty map", vec![]),
                (
                    "high RAM ending inside its first unit",
                    edit(&|m| m[2].1 = page(UNIT) - 1),
                ),
                ("a page count that wraps", edit(&|m| m[2].1 = u64::MAX)),
                (
                    "more RAM than the page tables reach",
                    edit(&|m| m[2].1 = page(MAP_LIMIT)),
                ),
                ("low RAM a page longer", edit(&|m| m[0].1 += 1)),
                ("low RAM not starting at zero", edit(&|m| m[0].0 = 1)),
                ("high RAM a unit late", edit(&|m| m[2].0 += page(UNIT))),
                ("KVM's range a page longer", edit(&|m| m[1].1 += 1)),
                ("KVM's range as RAM", edit(&|m| m[1].2 = mem)),
                ("low RAM as reserved", edit(&|m| m[0].2 = res)),
                (
                    "KVM's range left out",
                    edit(&|m| {
                        m.remove(1);
                    }),
                ),
                (
                    "an entry too many",
                    edit(&|m| m.push((page(MAP_LIMIT), 1, res))),
                ),
                ("entries out of order", edit(&|m| m.swap(0, 1))),
                (
                    "a small guest too small to hold the image",
                    vec![
                        (0, page(small) - page(UNIT), mem),
                        (page(KVM_IDENTITY), 4, res),
                    ],
                ),
            ];
            if snp {
                cases.push((
                    "HyperTransport left out",
                    edit(&|m| m.retain(|e| e.0 != ht.0)),
                ));
                cases.push((
                    "high RAM at 4 GiB running into HyperTransport",
                    edit(&|m| m[2].1 = page(AMD_HT_END - FOUR_GIB)),
                ));
            } else {
                cases.push(("HyperTransport on Intel", edit(&|m| m.push(ht))));
            }
            for (why, map) in cases {
                shim.loader_memory_map(&map);
                assert!(
                    shim.boot_map(&efi, &zero).is_none(),
                    "snp={snp}: {why} was accepted"
                );
            }
        }
    }

    /// Each component is SHA-256 of exactly `size` bytes at `address`, reset page included.
    #[test]
    fn every_component_hashes_the_bytes_at_the_address_it_names() {
        let (file, manifest) = built(&params());
        let loaded: BTreeMap<u64, Vec<u8>> = igvm_pages(&file)
            .unwrap()
            .into_iter()
            .filter_map(|p| p.data.map(|d| (p.gpa, d)))
            .collect();
        let components = manifest["components"].as_object().unwrap();
        assert_eq!(components.len(), 8);
        for (name, c) in components {
            let gpa =
                u64::from_str_radix(c["address"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap();
            let size = c["size"].as_u64().unwrap() as usize;
            let mut bytes = Vec::new();
            while bytes.len() < size {
                bytes.extend_from_slice(&loaded[&(gpa + bytes.len() as u64)]);
            }
            assert_eq!(
                hex::encode(Sha256::digest(&bytes[..size])),
                c["sha256"].as_str().unwrap(),
                "component {name} does not describe the bytes at its address",
            );
        }
    }

    /// Both manifests name their platform, so a reader does not have to guess
    /// whether expected_mrtd or expected_snp_measurement is the number.
    #[test]
    fn a_manifest_names_the_platform_it_measured() {
        let (_, manifest) = built(&params());
        assert_eq!(manifest["platform"], "tdx");
        assert!(manifest["expected_mrtd"].is_string());
    }

    /// A map that misses the aperture QEMU builds leaves no window for BARs.
    #[test]
    fn the_pci_aperture_follows_the_ram_the_machine_has() {
        let small = Params::tdx(2 * GIB, 1, "").unwrap();
        assert_eq!((small.memory, small.mmio.len()), (2 * GIB, 0));
        assert_eq!(Params::tdx(3 * GIB, 1, "").unwrap().memory, 5 * GIB);
        let p = Params::tdx(8 * GIB, 1, "").unwrap();
        assert_eq!(p.memory, 10 * GIB);
        // TDX loads the reset page inside the aperture; SNP loads nothing there.
        assert_eq!(p.mmio, vec![(2 * GIB, RESET_ALIAS - 2 * GIB)]);
        let snp = Params::snp(8 * GIB, DEFAULT_VCPUS, DEFAULT_CBIT, "").unwrap();
        assert_eq!(snp.mmio, vec![(2 * GIB, 2 * GIB)]);

        let placed: Vec<Placed> = p
            .mmio
            .iter()
            .map(|(base, size)| Placed::mmio(*base, *size))
            .chain([Placed::measured(
                RESET_ALIAS,
                "",
                RESERVED,
                vec![0u8; PAGE as usize],
            )])
            .collect();
        let e820 = boot::e820(&boot::spans(&placed), p.memory);
        assert!(e820
            .iter()
            .all(|(base, size, kind)| *kind != RAM || base + size <= 2 * GIB || *base >= 4 * GIB));
        assert!(e820
            .iter()
            .any(|(base, size, kind)| (*base, *size, *kind) == (4 * GIB, 6 * GIB, RAM)));
    }

    /// Past 4 GiB of map the reset page lies inside the guest's own address
    /// space, so the shape a large TDX guest takes reserves it in E820 and the
    /// shim accepts nothing there.
    #[test]
    fn a_large_guest_leaves_the_reset_page_out_of_its_ram() {
        let dir = tempdir().unwrap();
        let (_, launch) = launched(dir.path(), 8 * GIB, false);
        let e820 = launch.shapes[1].e820(&launch.spans, 10 * GIB);
        assert!(e820.contains(&(RESET_ALIAS, PAGE, RESERVED)));
        assert!(!e820.iter().any(|(base, size, kind)| *kind == RAM
            && *base < RESET_ALIAS + PAGE
            && RESET_ALIAS < base + size));
        assert!(!launch
            .accept
            .iter()
            .any(|(lo, hi)| *lo < RESET_ALIAS + PAGE && RESET_ALIAS < *hi));
    }

    /// The manifest describes the image. Anything the host picks at
    /// TDH.MNG.INIT is the verifier's platform policy, and stating it here
    /// would put a build artifact in the business of asserting host facts.
    #[test]
    fn the_launch_block_states_nothing_the_host_chooses() {
        let r = tdx_launch(&[7u8; 48], zeros(48));
        for host_chosen in [
            "attributes",
            "attributes_mask",
            "xfam",
            "mrowner",
            "mrownerconfig",
            "servtd_hash",
            "tee_tcb_svn",
        ] {
            assert!(!r.contains_key(host_chosen), "{host_chosen} is the host's");
        }
        // An exact set, so a newly added host field fails even though no
        // denylist names it.
        assert_eq!(
            r.keys().copied().collect::<Vec<_>>(),
            ["mrconfigid", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
        );
        // Distinct values, so the two cannot be swapped without failing.
        assert_eq!(r["mrtd"], hex::encode([7u8; 48]));
        assert_eq!(r["mrconfigid"], zeros(48));
        for rtmr in ["rtmr0", "rtmr1", "rtmr2", "rtmr3"] {
            assert_eq!(r[rtmr], zeros(48), "{rtmr} is not a reset value");
        }
    }

    /// The guest counts only E820 RAM toward its config, allowing
    /// tinfoil/cmd/boot/memory.go's imageReservedBytes for the pages this image
    /// reserves, so that allowance has to cover them at every size QEMU gives
    /// a whole number of units.
    #[test]
    fn e820_ram_falls_short_only_by_the_images_own_pages() {
        const GUEST_ALLOWANCE: u64 = 2 << 20;
        // Everything this image reserves sits below KERNEL_SETUP_END, but for
        // the TDX reset page.
        const { assert!(KERNEL_SETUP_END + PAGE <= GUEST_ALLOWANCE) };
        let dir = tempdir().unwrap();
        for snp in [false, true] {
            let (_, launch) = launched(dir.path(), 8 * GIB, snp);
            let shim = shim_for(&launch, snp);
            for ram in SIZES.into_iter().filter(|r| r.is_multiple_of(UNIT)) {
                shim.loader_memory_map(&qemu_map(ram, snp));
                let got = shim
                    .boot_map(
                        &placed_page(&launch, EFI_PAGE),
                        &placed_page(&launch, ZERO_PAGE),
                    )
                    .unwrap();
                let given: u64 = got.e820.iter().filter(|e| e.2 == RAM).map(|e| e.1).sum();
                assert!(
                    given <= ram && ram - given <= GUEST_ALLOWANCE,
                    "{given:#x} of RAM for {ram:#x}, snp={snp}"
                );
            }
        }
    }

    /// QEMU restacks a large AMD guest's high bank above 1 TiB and reserves
    /// the HyperTransport hole below it, which the guest must not count.
    #[test]
    fn e820_reserves_the_hypertransport_hole() {
        let (ht_lo, ht_hi) = (1012 * GIB, 1024 * GIB);
        let ram = 1024 * GIB;
        let (lo, hi) = (ht_hi, ht_hi + ram - Q35_LOWMEM);
        let extents = [(0, Q35_LOWMEM, true), (ht_lo, ht_hi, false), (lo, hi, true)];
        let (top, host) = boot::host_regions(&extents);
        let e820 = boot::e820(&host, top);
        assert!(e820.contains(&(ht_lo, ht_hi - ht_lo, RESERVED)));
        let given: u64 = e820.iter().filter(|e| e.2 == RAM).map(|e| e.1).sum();
        assert_eq!(given, ram);
    }
}

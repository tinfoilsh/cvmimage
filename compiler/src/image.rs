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
    let field = config_field(hash, 48)?;
    if field[64..].bytes().any(|b| b != b'0') {
        return Err("--config-hash must be a 32-byte config hash padded with 16 zero bytes".into());
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
    use tinfoil_firmware::boot::{RAM, RESERVED};

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

    /// The shim's data block, read back the way the shim reads it: the kernel
    /// entry point, the least memory the image runs in, and the placed spans.
    pub fn shim_data(page: &[u8]) -> (u64, u64, Vec<boot::Region>) {
        let word =
            |i: u64| u64::from_le_bytes(page[i as usize..i as usize + 8].try_into().unwrap());
        let mut spans = Vec::new();
        let mut at = SHIM_DATA + SHIM_DATA_SPANS;
        while word(at) != 0 || word(at + SPAN_HI) != 0 {
            spans.push((word(at), word(at + SPAN_HI), word(at + SPAN_KIND) as u32));
            at += SPAN_LEN;
        }
        (
            word(SHIM_DATA + SHIM_DATA_ENTRY),
            word(SHIM_DATA + SHIM_DATA_MIN_MEMORY),
            spans,
        )
    }

    /// The ranges the shim will accept in the guest `params` describes, from
    /// the spans its own page carries and the map the loader will report.
    pub fn shim_ranges(page: &[u8], params: &Params) -> (u64, Vec<(u64, u64)>) {
        let (entry, _, spans) = shim_data(page);
        let (top, host) = boot::host_regions(&params.extents());
        (entry, boot::accept_ranges(&boot::merge(&spans, &host), top))
    }

    #[test]
    fn the_shim_accepts_exactly_what_the_builder_did_not_place() {
        let params = params();
        let file = built(&params).0;
        let (entry, ranges) = shim_ranges(&reset_page(&file), &params);
        assert_eq!(entry, KERNEL_BASE + 0x200);

        let loaded: Vec<u64> = igvm_pages(&file)
            .unwrap()
            .iter()
            .map(|p| p.gpa)
            .filter(|gpa| *gpa < params.memory)
            .collect();
        // The loader accepted every page it loaded, and accepting one twice replaces it...
        for (lo, hi) in &ranges {
            assert!(lo < hi && *hi <= params.memory);
            assert!(!loaded.iter().any(|gpa| gpa >= lo && gpa < hi));
        }
        // ...the gaps between accepted ranges are exactly those pages...
        for pair in ranges.windows(2) {
            assert!(loaded.contains(&pair[0].1));
        }
        // ...and nothing below the top of memory is left out of either list.
        let accepted: u64 = ranges.iter().map(|(l, h)| h - l).sum();
        assert_eq!(accepted + loaded.len() as u64 * PAGE, params.memory);
        assert_eq!(ranges.first().unwrap().0, 0);
        assert_eq!(ranges.last().unwrap().1, params.memory);
    }

    /// The map the shim carries is measured, so it is one map for every guest
    /// the image can run in. For each of them it has to produce exactly what
    /// the builder would have produced knowing that guest's size -- including
    /// the q35 aperture, which the measured map always states and a guest too
    /// small to open one must never see.
    #[test]
    fn the_measured_map_describes_every_guest_the_image_can_run_in() {
        let dir = tempdir().unwrap();
        let (k, i) = (dir.path().join("bzImage"), dir.path().join("initrd"));
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        for ram in [
            align_up(INITRAMFS_BASE + 100_000, PAGE),
            DEFAULT_RAM,
            2 * GIB,
            Q35_SPLIT - PAGE,
            Q35_SPLIT,
            8 * GIB,
            1024 * GIB,
            MAX_RAM,
        ] {
            for snp in [false, true] {
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
                // What a builder that knew this guest's size would have laid
                // out for it: the placed map, aperture and all.
                let known = boot::spans(&launch.placed);
                let memory = params.memory;
                let (top, host) = boot::host_regions(&params.extents());
                assert_eq!(top, memory, "the top of RAM for {ram:#x}, snp={snp}");
                let merged = boot::merge(&launch.spans, &host);
                assert_eq!(
                    boot::e820(&merged, top),
                    boot::e820(&known, memory),
                    "the E820 map for {ram:#x} of RAM, snp={snp}"
                );
                assert_eq!(
                    boot::accept_ranges(&merged, top),
                    boot::accept_ranges(&known, memory),
                    "the accept ranges for {ram:#x} of RAM, snp={snp}"
                );
                // Nothing placed is ever accepted, at any size.
                for (lo, hi) in boot::accept_ranges(&merged, top) {
                    assert!(known.iter().all(|(a, b, _)| hi <= *a || lo >= *b));
                }
                // The least memory the shim will run in holds the initramfs.
                assert_eq!(
                    boot::min_memory(&launch.spans),
                    align_up(INITRAMFS_BASE + 100_000, PAGE)
                );
            }
        }
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

    /// Every guest size this image can be launched at, including both sides of
    /// the q35 aperture and both ends of the range.
    const SIZES: [u64; 9] = [
        0x2001_9000,
        DEFAULT_RAM,
        2 * GIB,
        Q35_SPLIT - PAGE,
        Q35_SPLIT,
        8 * GIB,
        64 * GIB,
        1024 * GIB,
        MAX_RAM,
    ];

    /// The shim's own assembly, run here against the map a real image carries
    /// and the extents a loader will describe. This is the whole point of
    /// taking these tables out of the measurement: one measured list of spans,
    /// and a shim that merges a host's map into it and arrives at exactly what
    /// boot.rs specifies for whatever machine the host built.
    #[test]
    fn the_shim_builds_the_map_boot_rs_specifies() {
        let dir = tempdir().unwrap();
        let shim = tinfoil_firmware::shim::shim();
        for snp in [false, true] {
            for ram in SIZES {
                let (params, launch) = launched(dir.path(), ram, snp);
                shim.data(launch.entry, &launch.spans).loader_ram(ram);
                let (top, host) = boot::host_regions(&params.extents());
                let want = boot::merge(&launch.spans, &host);
                assert_eq!(
                    shim.regions(),
                    Some((top, want.clone())),
                    "the regions for {ram:#x}, snp={snp}"
                );
                let e820 = shim.e820(top).unwrap();
                assert_eq!(
                    e820,
                    boot::e820(&want, top),
                    "the E820 map for {ram:#x}, snp={snp}"
                );
                // Whatever the loader says, Linux is handed a table that only
                // ascends: an entry that went backwards over another would be
                // left to e820__update_table to sort out.
                for pair in e820.windows(2) {
                    assert!(
                        pair[0].0 + pair[0].1 <= pair[1].0,
                        "the E820 map for {ram:#x} overlaps at {:#x}",
                        pair[1].0
                    );
                }
                assert_eq!(
                    shim.accept_ranges(top),
                    boot::accept_ranges(&want, top),
                    "the accept ranges for {ram:#x}, snp={snp}"
                );
            }
        }
    }

    /// QEMU moves a large guest's high memory above 1 TiB on AMD hosts, past
    /// the HyperTransport range it reserves (hw/i386/pc.c). The shim is told
    /// where RAM is rather than assuming, so it describes that machine too --
    /// with the reserved range reserved and the gap left for devices.
    #[test]
    fn a_map_with_memory_relocated_above_the_reserved_range_still_describes_it() {
        let dir = tempdir().unwrap();
        let shim = tinfoil_firmware::shim::shim();
        let (_, launch) = launched(dir.path(), 8 * GIB, true);
        // AMD_HT_START..AMD_ABOVE_1TB_START, and the RAM QEMU restacks above it.
        let (ht_lo, ht_hi) = (1012 * GIB, 1024 * GIB);
        let (lo, hi) = (1024 * GIB, 1536 * GIB);
        shim.data(launch.entry, &launch.spans).loader_memory_map(&[
            (0, Q35_LOWMEM / PAGE, MAP_TYPE_MEMORY as u16),
            (ht_lo / PAGE, (ht_hi - ht_lo) / PAGE, 1),
            (lo / PAGE, (hi - lo) / PAGE, MAP_TYPE_MEMORY as u16),
        ]);
        let extents = [(0, Q35_LOWMEM, true), (ht_lo, ht_hi, false), (lo, hi, true)];
        let (top, host) = boot::host_regions(&extents);
        let want = boot::merge(&launch.spans, &host);
        assert_eq!(shim.regions(), Some((top, want.clone())));
        let e820 = shim.e820(top).unwrap();
        assert_eq!(e820, boot::e820(&want, top));
        for pair in e820.windows(2) {
            assert!(pair[0].0 + pair[0].1 <= pair[1].0, "the E820 map overlaps");
        }
        // The aperture between the two banks of RAM belongs to no entry, the
        // reserved range is reserved, and the high bank is ordinary RAM.
        assert!(e820
            .iter()
            .all(|(b, n, k)| *k != RAM || b + n <= Q35_LOWMEM || *b >= lo));
        assert!(e820.contains(&(ht_lo, ht_hi - ht_lo, RESERVED)));
        assert!(e820.contains(&(lo, hi - lo, RAM)));
        // ...and nothing outside the RAM the loader described is accepted.
        for (l, h) in shim.accept_ranges(top) {
            assert!(h <= Q35_LOWMEM || (l >= lo && h <= hi), "{l:#x}..{h:#x}");
        }
    }

    /// A measured span and one of the loader's regions can begin at the same
    /// address -- the reset page sits at the top of the 32-bit space, where a
    /// map's aperture can begin too. The order the two are merged in decides
    /// the table, so it is pinned here rather than left to whichever list the
    /// shim happens to read first.
    #[test]
    fn a_region_beginning_where_a_placed_span_does_is_merged_the_same_way() {
        let dir = tempdir().unwrap();
        let shim = tinfoil_firmware::shim::shim();
        let (_, launch) = launched(dir.path(), 8 * GIB, false);
        let ram = MAP_TYPE_MEMORY as u16;
        // Low RAM stopping exactly at the reset page, so the aperture after it
        // and the page itself begin together.
        let extents = [(0, RESET_ALIAS, true), (FOUR_GIB, 6 * GIB, true)];
        shim.data(launch.entry, &launch.spans).loader_memory_map(&[
            (0, RESET_ALIAS / PAGE, ram),
            (FOUR_GIB / PAGE, 2 * GIB / PAGE, ram),
        ]);
        let (top, host) = boot::host_regions(&extents);
        let want = boot::merge(&launch.spans, &host);
        assert!(want.iter().filter(|(lo, _, _)| *lo == RESET_ALIAS).count() == 2);
        assert_eq!(shim.regions(), Some((top, want.clone())));
        assert_eq!(shim.e820(top), Some(boot::e820(&want, top)));
        assert_eq!(shim.accept_ranges(top), boot::accept_ranges(&want, top));
        // Whichever way round they are merged, the reset page is not accepted.
        for (lo, hi) in shim.accept_ranges(top) {
            assert!(hi <= RESET_ALIAS || lo >= RESET_ALIAS + PAGE);
        }
    }

    /// QEMU reserves the HyperTransport range on any AMD host with a wide
    /// enough address space, whatever size the guest is, and a host may
    /// describe anything else it likes above the RAM it gave out. None of it
    /// changes a guest that ends below it.
    #[test]
    fn regions_above_the_guests_ram_change_nothing_in_it() {
        let dir = tempdir().unwrap();
        let shim = tinfoil_firmware::shim::shim();
        let (params, launch) = launched(dir.path(), 8 * GIB, true);
        let ram = MAP_TYPE_MEMORY as u16;
        shim.data(launch.entry, &launch.spans).loader_ram(8 * GIB);
        let plain = (
            shim.regions().unwrap().0,
            shim.e820(params.memory),
            shim.accept_ranges(params.memory),
        );

        shim.loader_memory_map(&[
            (0, Q35_LOWMEM / PAGE, ram),
            (FOUR_GIB / PAGE, (params.memory - FOUR_GIB) / PAGE, ram),
            // AMD_HT_START..AMD_ABOVE_1TB_START, and something past the map.
            (1012 * GIB / PAGE, 12 * GIB / PAGE, 1),
            (4096 * GIB / PAGE, GIB / PAGE, 1),
        ]);
        assert_eq!(shim.regions().unwrap().0, plain.0);
        assert_eq!(shim.e820(params.memory), plain.1);
        assert_eq!(shim.accept_ranges(params.memory), plain.2);
    }

    /// A loader can describe a region that covers a page this image placed --
    /// the reset page sits where a host is free to call the whole top of the
    /// 32-bit space reserved. Two entries for the same bytes would be a table
    /// that goes backwards, so the second is folded into the first.
    #[test]
    fn a_region_swallowing_a_placed_page_still_leaves_an_ascending_table() {
        let dir = tempdir().unwrap();
        let shim = tinfoil_firmware::shim::shim();
        let (_, launch) = launched(dir.path(), 8 * GIB, false);
        let ram = MAP_TYPE_MEMORY as u16;
        let min = boot::min_memory(&launch.spans);
        shim.data(launch.entry, &launch.spans).loader_memory_map(&[
            (0, min / PAGE, ram),
            (0xffff_0000 / PAGE, 0x1_0000 / PAGE, 1),
            (FOUR_GIB / PAGE, 4 * GIB / PAGE, ram),
        ]);
        let extents = [
            (0, min, true),
            (0xffff_0000, FOUR_GIB, false),
            (FOUR_GIB, FOUR_GIB + 4 * GIB, true),
        ];
        let (top, host) = boot::host_regions(&extents);
        let want = boot::merge(&launch.spans, &host);
        assert_eq!(shim.regions(), Some((top, want.clone())));
        let e820 = shim.e820(top).unwrap();
        assert_eq!(e820, boot::e820(&want, top));
        for pair in e820.windows(2) {
            assert!(
                pair[0].0 + pair[0].1 <= pair[1].0,
                "the E820 map overlaps at {:#x}",
                pair[1].0
            );
        }
        // The reset page is inside that region, so it is reserved either way...
        assert!(e820
            .iter()
            .any(|(b, n, k)| *b <= RESET_ALIAS && RESET_ALIAS < b + n && *k == RESERVED));
        // ...and still never accepted.
        for (lo, hi) in shim.accept_ranges(top) {
            assert!(hi <= RESET_ALIAS || lo >= RESET_ALIAS + PAGE);
        }
    }

    /// The memory map is unmeasured and the host writes it. Every map this
    /// image cannot describe has to terminate the shim, not be clamped into
    /// range: a clamped map is a guest whose E820 table and whose RAM disagree.
    #[test]
    fn a_memory_map_this_image_cannot_run_in_is_refused() {
        let dir = tempdir().unwrap();
        let shim = tinfoil_firmware::shim::shim();
        let (params, launch) = launched(dir.path(), 8 * GIB, false);
        shim.data(launch.entry, &launch.spans);
        let min = boot::min_memory(&launch.spans);
        let ram = MAP_TYPE_MEMORY as u16;

        // The map a working guest presents, so the refusals below are the only
        // thing that differs.
        shim.loader_ram(8 * GIB);
        assert_eq!(shim.regions().map(|(top, _)| top), Some(params.memory));

        let long: Vec<(u64, u64, u16)> = (0..=MAP_ENTRIES).map(|n| (n * 2 + 1, 1, ram)).collect();
        for (why, map) in [
            ("an empty map", vec![]),
            ("no memory at all", vec![(0, 0, ram)]),
            (
                "less than the image places in it",
                vec![(0, min / PAGE - 1, ram)],
            ),
            (
                "more than the page tables reach",
                vec![
                    (0, Q35_LOWMEM / PAGE, ram),
                    (FOUR_GIB / PAGE, (MAX_MEMORY - FOUR_GIB) / PAGE + 1, ram),
                ],
            ),
            ("a page count that wraps", vec![(1, u64::MAX, ram)]),
            (
                "extents that do not ascend",
                vec![
                    (FOUR_GIB / PAGE, GIB / PAGE, ram),
                    (0, Q35_LOWMEM / PAGE, ram),
                ],
            ),
            (
                "extents that overlap",
                vec![(0, 8 * GIB / PAGE, ram), (FOUR_GIB / PAGE, GIB / PAGE, ram)],
            ),
            (
                "memory that does not start at zero",
                vec![(1, 8 * GIB / PAGE, ram)],
            ),
            (
                "the image's own pages declared reserved",
                vec![(0, 8 * GIB / PAGE, 1)],
            ),
            ("more extents than the shim reads", long),
        ] {
            shim.loader_memory_map(&map);
            assert_eq!(shim.regions(), None, "{why} was accepted");
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
        assert_eq!(components.len(), 6);
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

    /// Past 4 GiB of map the reset page lies inside the guest's own address space.
    #[test]
    fn a_large_guest_leaves_the_reset_page_out_of_its_ram() {
        let params = Params::tdx(8 * GIB, DEFAULT_VCPUS, "").unwrap();
        let (_, ranges) = shim_ranges(&reset_page(&built(&params).0), &params);
        assert!(ranges
            .iter()
            .all(|(lo, hi)| *hi <= RESET_ALIAS || *lo >= RESET_ALIAS + PAGE));
        assert_eq!(ranges.last().unwrap(), &(RESET_ALIAS + PAGE, params.memory));
        // The same placement reserves it in E820, so Linux does not take it for free RAM.
        let e820 = boot::e820(
            &boot::spans(&[Placed::measured(
                RESET_ALIAS,
                "",
                RESERVED,
                vec![0u8; PAGE as usize],
            )]),
            params.memory,
        );

        assert!(e820
            .iter()
            .any(|(base, size, kind)| *base == RESET_ALIAS && *size == PAGE && *kind == RESERVED));
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
}

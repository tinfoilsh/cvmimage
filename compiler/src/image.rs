use crate::mrtd;
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_TDX_PLATFORM_VERSION,
    IGVM_VHS_SUPPORTED_PLATFORM,
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
    let mrconfigid = config_field(config_hash, 48)?;
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
        format_version: 2,
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

fn launch_pages(placed: &[Placed]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut out = Vec::new();
    for region in placed {
        match &region.fill {
            Fill::Measured(data) => out.extend(boot::pages(region.base, data)),
            Fill::Mmio(_) => {}
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

fn igvm(pages: &[(u64, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let platform = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: COMPAT,
        highest_vtl: 0,
        platform_type: IgvmPlatformType::TDX,
        platform_version: IGVM_TDX_PLATFORM_VERSION,
        // Nothing is loaded shared and the guest reads its own GPAW, so no boundary is stated.
        shared_gpa_boundary: 0,
    });
    let directives = pages
        .iter()
        .map(|(gpa, data)| page_directive(*gpa, IgvmPageDataType::NORMAL, data.clone()))
        .collect();
    let file = IgvmFile::new(IgvmRevision::V1, vec![platform], vec![], directives)
        .map_err(|e| format!("construct TDX IGVM: {e}"))?;
    let mut out = Vec::new();
    file.serialize(&mut out)
        .map_err(|e| format!("serialize TDX IGVM: {e}"))?;
    Ok(out)
}

/// Reads an image back the way a loader does, refusing any directive that is not a measured page.
fn igvm_pages(file: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    IgvmFile::new_from_binary(file, None)
        .map_err(|e| format!("read back TDX IGVM: {e}"))?
        .directives()
        .iter()
        .map(|d| match d {
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
                Ok((*gpa, data.clone()))
            }
            _ => Err("TDX IGVM carries a directive that is not a measured page".to_string()),
        })
        .collect()
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
    // MEM.PAGE.ADD folds pages in file order, so a file whose pages descend or
    // overlap measures to a value no hardware will report.
    for pair in pages.windows(2) {
        if pair[0].0 + PAGE > pair[1].0 {
            return Err(format!(
                "TDX pages are not in ascending order, or overlap, at {:#x}",
                pair[1].0
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

        let moved = mrtd(&kernel, &initramfs, cmdline, DEFAULT_VCPUS + 1);
        assert_ne!(
            base, moved,
            "the processor count left the measurement alone"
        );
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
        let (gpa, page) = igvm_pages(file).unwrap().pop().unwrap();
        assert_eq!(gpa, RESET_ALIAS);
        page
    }

    #[test]
    fn builds_a_byte_identical_loadable_igvm_file() {
        let one = built(&params()).0;
        assert_eq!(one, built(&params()).0);
        // Read back the way a loader does: whole measured pages in ascending order.
        let pages = igvm_pages(&one).unwrap();
        assert!(pages.windows(2).all(|w| w[0].0 + PAGE <= w[1].0));
        // The architectural reset instruction is the last 16 bytes of memory.
        assert_eq!(reset_page(&one)[PAGE as usize - 16], 0xe9);
    }

    pub fn shim_ranges(page: &[u8]) -> (u64, Vec<(u64, u64)>) {
        let at = SHIM_DATA as usize;
        let word = |i: usize| u64::from_le_bytes(page[i..i + 8].try_into().unwrap());
        let mut ranges = Vec::new();
        let mut i = at + 8;
        while word(i) != 0 || word(i + 8) != 0 {
            ranges.push((word(i), word(i + 8)));
            i += 16;
        }
        (word(at), ranges)
    }

    #[test]
    fn the_shim_accepts_exactly_what_the_builder_did_not_place() {
        let params = params();
        let file = built(&params).0;
        let (entry, ranges) = shim_ranges(&reset_page(&file));
        assert_eq!(entry, KERNEL_BASE + 0x200);

        let loaded: Vec<u64> = igvm_pages(&file)
            .unwrap()
            .iter()
            .map(|(gpa, _)| *gpa)
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

    /// Each component is SHA-256 of exactly `size` bytes at `address`, reset page included.
    #[test]
    fn every_component_hashes_the_bytes_at_the_address_it_names() {
        let (file, manifest) = built(&params());
        let loaded: BTreeMap<u64, Vec<u8>> = igvm_pages(&file).unwrap().into_iter().collect();
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
        let e820 = boot::e820(&placed, p.memory);
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
        let (_, ranges) = shim_ranges(&reset_page(&built(&params).0));
        assert!(ranges
            .iter()
            .all(|(lo, hi)| *hi <= RESET_ALIAS || *lo >= RESET_ALIAS + PAGE));
        assert_eq!(ranges.last().unwrap(), &(RESET_ALIAS + PAGE, params.memory));
        // The same placement reserves it in E820, so Linux does not take it for free RAM.
        let e820 = boot::e820(
            &[Placed::measured(
                RESET_ALIAS,
                "",
                RESERVED,
                vec![0u8; PAGE as usize],
            )],
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

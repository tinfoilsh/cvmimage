use crate::image::{
    component, components, config_field, mmio_holes, page_directive, param_gpa,
    parameter_directives, write_manifest, zeros, Component, ReportFields, COMPAT, PARAM_AREA,
    PARAM_MAP_AREA, PARAM_OFFSET, PARAM_PAGES,
};
use igvm::{
    IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY,
    IGVM_VHS_SNP_ID_BLOCK_SIGNATURE, IGVM_VHS_SUPPORTED_PLATFORM,
};
use p384::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use serde::Serialize;
use sha2::{Digest, Sha384};
use std::{collections::BTreeMap, fs, path::Path};
use tinfoil_firmware::{
    boot::{self, Fill},
    io_error,
    layout::*,
    vmsa::{ap_vmsa, bsp_vmsa, validate_vmsa, vmsa_page},
};
use zerocopy::FromZeroes;

// IGVM states a required-memory span in 32 bits, so a larger guest takes several.
const REQUIRED_MEMORY_MAX: u64 = 0xffff_f000;

// The PAGE_INFO structure SNP_LAUNCH_UPDATE digests, one per launch page.
const PAGE_INFO_LEN: u16 = 112;
const PAGE_INFO_CONTENTS: usize = 48;
const PAGE_INFO_LENGTH: usize = 96;
const PAGE_INFO_TYPE: usize = 98;
const PAGE_INFO_GPA: usize = 104;
const PAGE_NORMAL: u8 = 1;
const PAGE_VMSA: u8 = 2;
// Not 3, which is ZERO: the type is part of what the firmware digests.
const PAGE_UNMEASURED: u8 = 4;
const PAGE_SECRETS: u8 = 5;
const PAGE_CPUID: u8 = 6;

// "SEV Secure Nested Paging Firmware ABI" 8.18: ECDSA P-384 over SHA-384.
const ID_KEY_ECDSA_P384: u32 = 1;
const ID_CURVE_P384: u32 = 2;
// QEMU stamps this version into the block, so the signature covers the same value.
const ID_BLOCK_VERSION: u32 = 1;
// The block the firmware verifies, and the fields the signature covers.
const ID_BLOCK_LEN: usize = 0x60;
const ID_BLOCK_LD: usize = 0;
const ID_BLOCK_VERSION_AT: usize = 0x50;
const ID_BLOCK_SVN: usize = 0x54;
const ID_BLOCK_POLICY: usize = 0x58;
// The firmware's own public key structure, which ID_KEY_DIGEST is taken over.
const SEV_KEY_LEN: usize = 0x404;
const SEV_KEY_CURVE: usize = 0;
const SEV_KEY_QX: usize = 4;
const SEV_KEY_QY: usize = 76;
const ECDSA_COMPONENT_LEN: usize = 72;

#[derive(Clone)]
struct LaunchPage {
    gpa: u64,
    data: Vec<u8>,
    /// The PAGE_INFO type SNP_LAUNCH_UPDATE stamps on the page.
    kind: u8,
}

#[derive(Serialize)]
struct Topology {
    sockets: u8,
    cores: u32,
    threads_per_core: u8,
    vcpus: u32,
}
#[derive(Serialize)]
struct Manifest {
    format_version: u32,
    platform: &'static str,
    memory_bytes: u64,
    topology: Topology,
    command_line: String,
    mmio_holes: Vec<String>,
    kernel_entry: String,
    expected_snp_measurement: String,
    guest_policy: String,
    c_bit_position: u8,
    sev_features: String,
    shim_owned_bytes: usize,
    launch: ReportFields,
    components: BTreeMap<&'static str, Component>,
}

pub fn build(
    kernel_path: &Path,
    initramfs_path: &Path,
    output: &Path,
    params: &Params,
    config_hash: Option<&str>,
    id_key: Option<&Path>,
    guest_svn: u32,
) -> Result<(), String> {
    // An SVN reaches the guest only inside a signed ID block. Without one the
    // firmware reports zero, so accepting a number here would put a value in
    // the manifest that no honest launch of this image can produce.
    if guest_svn != 0 && id_key.is_none() {
        return Err("--guest-svn needs --id-key: an unsigned launch reports SVN 0".into());
    }
    let host_data = config_field(config_hash, 32)?;
    let launch = tinfoil_firmware::snp(kernel_path, initramfs_path, params)?;
    let placed = launch.placed;
    let required_memory = launch.required_memory;
    let owned = launch.shim_owned;

    // The parameter area first, in the order a loader imports it: see image::launch_pages.
    let mut pages = Vec::new();
    for region in &placed {
        if matches!(region.fill, Fill::Parameters) {
            add_special(&mut pages, region.base, PAGE_UNMEASURED);
        }
    }
    for region in &placed {
        match &region.fill {
            // The loader and firmware fill these two, so both are measured by address alone.
            Fill::Host if region.base == SNP_CPUID => {
                add_special(&mut pages, region.base, PAGE_CPUID)
            }
            Fill::Host => add_special(&mut pages, region.base, PAGE_SECRETS),
            Fill::Measured(data) => add_normal(&mut pages, region.base, data),
            Fill::Parameters | Fill::Mmio(_) => {}
        }
    }
    validate_pages(&pages)?;

    // One measured VMSA per processor.
    let bsp_vmsa = bsp_vmsa();
    validate_vmsa(&bsp_vmsa, SHIM_BASE, BSP_STACK_TOP, ZERO_PAGE)?;
    let ap_vmsa = ap_vmsa();
    validate_vmsa(&ap_vmsa, SNP_AP_ENTRY, 0, 0)?;
    let vmsa = vmsa_page(&bsp_vmsa);
    let ap_page = vmsa_page(&ap_vmsa);
    let mut vmsa_pages = vec![vmsa.clone()];
    vmsa_pages.extend((1..params.vcpus).map(|_| ap_page.clone()));
    let measurement = launch_measurement(&pages, &vmsa_pages);
    // The loader must find memory wherever E820 claims some and none in the apertures.
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for (base, size, _) in &required_memory {
        match spans.last_mut() {
            Some(last) if last.1 == *base => last.1 = base + size,
            _ => spans.push((*base, base + size)),
        }
    }
    let mut directives = Vec::new();
    for (base, end) in spans {
        let mut at = base;
        while at < end {
            let bytes = (end - at).min(REQUIRED_MEMORY_MAX);
            directives.push(IgvmDirectiveHeader::RequiredMemory {
                gpa: at,
                compatibility_mask: COMPAT,
                number_of_bytes: bytes as u32,
                vtl2_protectable: false,
            });
            at += bytes;
        }
    }
    for p in &pages {
        match p.kind {
            PAGE_UNMEASURED => directives.extend(parameter_directives(p.gpa)?),
            kind => directives.push(page_directive(p.gpa, igvm_type(kind), p.data.clone())),
        }
    }
    // KVM consumes the VMSAs last and only at this architectural high GPA, which
    // QEMU checks per context; the vp index is what separates them.
    for vp_index in 0..params.vcpus as u16 {
        directives.push(IgvmDirectiveHeader::SnpVpContext {
            gpa: SNP_VMSA,
            compatibility_mask: COMPAT,
            vp_index,
            vmsa: if vp_index == 0 {
                bsp_vmsa.clone()
            } else {
                ap_vmsa.clone()
            },
        });
    }
    let signed = match id_key {
        None => None,
        Some(path) => {
            let pem = fs::read_to_string(path).map_err(io_error("read ID key"))?;
            let block = id_block(&pem, &measurement, guest_svn)?;
            directives.push(block.header);
            Some(block.key_digest)
        }
    };
    let platform = IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: COMPAT,
        highest_vtl: 0,
        platform_type: IgvmPlatformType::SEV_SNP,
        platform_version: 1,
        shared_gpa_boundary: 0,
    });
    let file = IgvmFile::new(
        IgvmRevision::V1,
        vec![platform],
        vec![IgvmInitializationHeader::GuestPolicy {
            policy: SNP_GUEST_POLICY,
            compatibility_mask: COMPAT,
        }],
        directives,
    )
    .map_err(|e| format!("construct SNP IGVM: {e}"))?;
    let mut serialized = Vec::new();
    file.serialize(&mut serialized)
        .map_err(|e| format!("serialize SNP IGVM: {e}"))?;
    // Read the file back the way a loader will, before publishing a digest for
    // it: the order directives are stated in is part of what they measure.
    if measure_snp(&serialized)? != measurement {
        return Err("emitted SNP IGVM does not measure what this build computed".into());
    }
    fs::write(output, &serialized).map_err(io_error("write SNP IGVM"))?;

    let mut components = components(&placed);
    components.insert("vmsa", component(SNP_VMSA, &vmsa));
    if params.vcpus > 1 {
        components.insert("vmsa_ap", component(SNP_VMSA, &ap_page));
    }
    let manifest = Manifest {
        format_version: 3,
        platform: "sev-snp",
        memory_bytes: params.memory,
        topology: Topology {
            sockets: 1,
            cores: params.vcpus,
            threads_per_core: 1,
            vcpus: params.vcpus,
        },
        command_line: params.cmdline.clone(),
        mmio_holes: mmio_holes(params),
        kernel_entry: format!("0x{:08x}", launch.entry),
        expected_snp_measurement: hex::encode(measurement),
        guest_policy: format!("0x{SNP_GUEST_POLICY:016x}"),
        c_bit_position: params.cbit,
        sev_features: format!("0x{SNP_SEV_FEATURES:016x}"),
        shim_owned_bytes: owned,
        launch: snp_launch(&measurement, host_data, guest_svn, signed),
        components,
    };
    write_manifest(output, &manifest)
}

// SNP_LAUNCH_FINISH fails unless the digest and policy match this signed block.
struct IdBlock {
    header: IgvmDirectiveHeader,
    key_digest: [u8; 48],
}

fn id_block(pem: &str, ld: &[u8; 48], guest_svn: u32) -> Result<IdBlock, String> {
    let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| format!("parse ID key: {e}"))?;
    // QEMU rebuilds the block from the IGVM header, so the signature covers these bytes.
    let mut block = [0u8; ID_BLOCK_LEN];
    block[ID_BLOCK_LD..ID_BLOCK_LD + 48].copy_from_slice(ld);
    block[ID_BLOCK_VERSION_AT..ID_BLOCK_VERSION_AT + 4]
        .copy_from_slice(&ID_BLOCK_VERSION.to_le_bytes());
    block[ID_BLOCK_SVN..ID_BLOCK_SVN + 4].copy_from_slice(&guest_svn.to_le_bytes());
    block[ID_BLOCK_POLICY..ID_BLOCK_POLICY + 8].copy_from_slice(&SNP_GUEST_POLICY.to_le_bytes());
    let signature: Signature = key.sign(&block);
    let point = key.verifying_key().to_encoded_point(false);
    let public = IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY {
        curve: ID_CURVE_P384,
        reserved: 0,
        qx: le72(point.x().ok_or("ID key is not an affine point")?),
        qy: le72(point.y().ok_or("ID key is not an affine point")?),
    };
    Ok(IdBlock {
        key_digest: key_digest(&public),
        header: IgvmDirectiveHeader::SnpIdBlock {
            compatibility_mask: COMPAT,
            author_key_enabled: 0,
            reserved: [0; 3],
            ld: *ld,
            family_id: [0; 16],
            image_id: [0; 16],
            version: ID_BLOCK_VERSION,
            guest_svn,
            id_key_algorithm: ID_KEY_ECDSA_P384,
            author_key_algorithm: 0,
            id_key_signature: Box::new(IGVM_VHS_SNP_ID_BLOCK_SIGNATURE {
                r_comp: le72(&signature.r().to_bytes()),
                s_comp: le72(&signature.s().to_bytes()),
            }),
            id_public_key: Box::new(public),
            author_key_signature: Box::new(IGVM_VHS_SNP_ID_BLOCK_SIGNATURE::new_zeroed()),
            author_public_key: Box::new(IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY::new_zeroed()),
        },
    })
}

// The firmware stores every ECDSA component little-endian in a 72-byte field.
fn le72(big_endian: &[u8]) -> [u8; ECDSA_COMPONENT_LEN] {
    let mut v = [0u8; ECDSA_COMPONENT_LEN];
    for (at, byte) in big_endian.iter().rev().enumerate() {
        v[at] = *byte;
    }
    v
}

// ID_KEY_DIGEST is SHA-384 over the firmware's key structure, not the IGVM one.
fn key_digest(public: &IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY) -> [u8; 48] {
    let mut sev_key = [0u8; SEV_KEY_LEN];
    sev_key[SEV_KEY_CURVE..SEV_KEY_CURVE + 4].copy_from_slice(&public.curve.to_le_bytes());
    sev_key[SEV_KEY_QX..SEV_KEY_QX + ECDSA_COMPONENT_LEN].copy_from_slice(&public.qx);
    sev_key[SEV_KEY_QY..SEV_KEY_QY + ECDSA_COMPONENT_LEN].copy_from_slice(&public.qy);
    Sha384::digest(sev_key).into()
}

// What a verifier should expect the report to say for this image: the digest,
// and the launch values this build chose. PLATFORM_INFO, SIGNER_INFO,
// REPORTED_TCB and VMPL describe the machine instead, so they belong to the
// verifier's platform policy and are not stated here.
fn snp_launch(
    measurement: &[u8; 48],
    host_data: String,
    guest_svn: u32,
    signed: Option<[u8; 48]>,
) -> ReportFields {
    let mut r = ReportFields::new();
    r.insert("measurement", hex::encode(measurement));
    // The file asks for this policy, but only a signed ID block makes the
    // firmware refuse a launch that used a different one, so a verifier has to
    // pin it either way.
    r.insert("policy", format!("0x{SNP_GUEST_POLICY:016x}"));
    r.insert("guest_svn", guest_svn.to_string());
    r.insert("host_data", host_data);
    // Zero says the firmware compared its launch digest against nothing.
    r.insert("id_key_digest", signed.map_or(zeros(48), hex::encode));
    r
}

fn launch_measurement(pages: &[LaunchPage], vmsas: &[Vec<u8>]) -> [u8; 48] {
    let mut digest = [0u8; 48];
    for p in pages {
        digest = extend(digest, p.gpa, p.kind, &p.data);
    }
    // KVM updates the VMSAs in vp index order once the pages are in, so the
    // digest takes them in that order too.
    for vmsa in vmsas {
        digest = extend(digest, SNP_VMSA, PAGE_VMSA, vmsa);
    }
    digest
}

// The directive that carries a page of each type to the loader. The parameter
// area is not page data at all, so it has none.
fn igvm_type(kind: u8) -> IgvmPageDataType {
    match kind {
        PAGE_SECRETS => IgvmPageDataType::SECRETS,
        PAGE_CPUID => IgvmPageDataType::CPUID_DATA,
        _ => IgvmPageDataType::NORMAL,
    }
}

// SNP_LAUNCH_UPDATE hashes page contents only for NORMAL and VMSA pages.
fn extend(old: [u8; 48], gpa: u64, kind: u8, page: &[u8]) -> [u8; 48] {
    let content: [u8; 48] = match kind {
        PAGE_NORMAL | PAGE_VMSA => Sha384::digest(page).into(),
        _ => [0u8; 48],
    };
    let mut info = [0u8; PAGE_INFO_LEN as usize];
    info[..PAGE_INFO_CONTENTS].copy_from_slice(&old);
    info[PAGE_INFO_CONTENTS..PAGE_INFO_LENGTH].copy_from_slice(&content);
    info[PAGE_INFO_LENGTH..PAGE_INFO_TYPE].copy_from_slice(&PAGE_INFO_LEN.to_le_bytes());
    info[PAGE_INFO_TYPE] = kind;
    info[PAGE_INFO_GPA..PAGE_INFO_GPA + 8].copy_from_slice(&gpa.to_le_bytes());
    Sha384::digest(info).into()
}
fn add_normal(out: &mut Vec<LaunchPage>, base: u64, data: &[u8]) {
    out.extend(boot::pages(base, data).map(|(gpa, data)| LaunchPage {
        gpa,
        data,
        kind: PAGE_NORMAL,
    }));
}
fn add_special(out: &mut Vec<LaunchPage>, gpa: u64, kind: u8) {
    out.push(LaunchPage {
        gpa,
        data: vec![0; PAGE as usize],
        kind,
    });
}
fn validate_pages(p: &[LaunchPage]) -> Result<(), String> {
    let mut stated: Vec<u64> = p.iter().map(|p| p.gpa).collect();
    stated.sort_unstable();
    if stated.windows(2).any(|w| w[0] == w[1]) {
        return Err("SNP image states a page more than once".into());
    }
    // The loader's own page is imported before these, so it is not among them.
    let measured: Vec<u64> = p
        .iter()
        .filter(|p| p.kind != PAGE_UNMEASURED)
        .map(|p| p.gpa)
        .collect();
    for w in measured.windows(2) {
        if w[0] + PAGE > w[1] {
            return Err(format!(
                "SNP launch pages are not in ascending order, or overlap, at {:#x}",
                w[1]
            ));
        }
    }
    Ok(())
}

/// Recompute the AMD SEV-SNP launch digest from a serialized image.
pub fn measure_snp(file: &[u8]) -> Result<[u8; 48], String> {
    let parsed =
        IgvmFile::new_from_binary(file, None).map_err(|e| format!("read back SNP IGVM: {e}"))?;
    let mut pages: Vec<LaunchPage> = Vec::new();
    let mut vmsas: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut id_block_ld: Option<[u8; 48]> = None;
    for directive in parsed.directives() {
        match directive {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
                flags,
                data_type,
                data,
            } if *compatibility_mask == COMPAT => {
                if flags.is_2mb_page() || flags.unmeasured() || flags.shared() {
                    return Err(format!(
                        "SNP IGVM page at {gpa:#x} is not a measured 4K page"
                    ));
                }
                // Normal pages are hashed, so length must be exact. The
                // firmware fills CPUID and secrets, whose contents are not
                // hashed at all.
                if *data_type == IgvmPageDataType::NORMAL && data.len() != PAGE as usize {
                    return Err(format!(
                        "SNP IGVM normal page at {gpa:#x} is {} bytes, expected {PAGE}",
                        data.len()
                    ));
                }
                pages.push(LaunchPage {
                    gpa: *gpa,
                    data: if *data_type == IgvmPageDataType::NORMAL {
                        data.clone()
                    } else {
                        vec![0; PAGE as usize]
                    },
                    kind: match *data_type {
                        IgvmPageDataType::SECRETS => PAGE_SECRETS,
                        IgvmPageDataType::CPUID_DATA => PAGE_CPUID,
                        _ => PAGE_NORMAL,
                    },
                });
            }
            IgvmDirectiveHeader::SnpVpContext {
                gpa,
                compatibility_mask,
                vp_index,
                vmsa,
            } if *compatibility_mask == COMPAT && *gpa == SNP_VMSA => {
                vmsas.push((*vp_index, vmsa_page(vmsa)));
            }
            IgvmDirectiveHeader::RequiredMemory { .. } => {}
            // The loader imports the whole area, so a larger one is more
            // unmeasured pages than the digest below accounts for.
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
            // Unmeasured contents, but the address they are imported at is not.
            IgvmDirectiveHeader::ParameterInsert(p)
                if p.compatibility_mask == COMPAT
                    && param_gpa(p.parameter_area_index) == Some(p.gpa) =>
            {
                if pages.iter().any(|p| p.kind != PAGE_UNMEASURED) {
                    return Err("SNP IGVM inserts a parameter area after page data".into());
                }
                pages.push(LaunchPage {
                    gpa: p.gpa,
                    data: vec![0; PAGE as usize],
                    kind: PAGE_UNMEASURED,
                });
            }
            // Not hashed, but it states what the digest must be.
            IgvmDirectiveHeader::SnpIdBlock { ld, .. } => id_block_ld = Some(*ld),
            _ => return Err("SNP IGVM carries a directive that is not a measured page".to_string()),
        }
    }
    if vmsas.is_empty() {
        return Err("SNP IGVM carries no save area, so it measures no processor".into());
    }
    // Every unmeasured page this image asks for, imported exactly once and
    // before anything the digest covers.
    let parameters: Vec<u64> = pages
        .iter()
        .filter(|p| p.kind == PAGE_UNMEASURED)
        .map(|p| p.gpa)
        .collect();
    if parameters != PARAM_PAGES {
        return Err(format!(
            "SNP IGVM inserts parameter areas at {parameters:#x?}, expected {PARAM_PAGES:#x?}"
        ));
    }
    // Deliberately not sorted: the digest folds pages in the order a loader
    // issues them, so sorting would measure a file that was never shipped.
    validate_pages(&pages)?;
    // Save areas are applied in processor index order, one per processor from
    // zero, so anything but a gapless 0..n cannot be launched.
    vmsas.sort_by_key(|(index, _)| *index);
    if vmsas
        .iter()
        .enumerate()
        .any(|(n, (index, _))| *index as usize != n)
    {
        return Err(format!(
            "SNP IGVM carries save areas for processors {:?}, expected 0..{}",
            vmsas.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vmsas.len()
        ));
    }
    let vmsa_pages: Vec<Vec<u8>> = vmsas.into_iter().map(|(_, page)| page).collect();
    let measurement = launch_measurement(&pages, &vmsa_pages);
    // A signed image commits to its own digest; if the block disagrees the
    // firmware refuses the launch.
    if let Some(ld) = id_block_ld {
        if ld != measurement {
            return Err(format!(
                "SNP IGVM ID block commits to {} but its pages measure {}",
                hex::encode(ld),
                hex::encode(measurement)
            ));
        }
    }
    Ok(measurement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::tests::{params, test_kernel};
    use tempfile::tempdir;
    use tinfoil_firmware::boot::RESERVED;

    #[test]
    fn measurement_matches_the_reference_implementation() {
        // Known answer from sev-snp-measure over one normal, Secrets, CPUID and VMSA page.
        let mut p = Vec::new();
        let mut data = vec![0u8; PAGE as usize];
        data[0] = 1;
        add_normal(&mut p, 0x1000, &data);
        add_special(&mut p, 0x2000, PAGE_SECRETS);
        add_special(&mut p, 0x3000, PAGE_CPUID);
        assert_eq!(
            hex::encode(launch_measurement(&p, &[vec![0u8; PAGE as usize]])),
            "64fba8d7f08e6c2b07f7a3fd610e2965a1683a3ca18ad66a73acc84e5cc2ebfb\
1721d1bcfebf8752aeac62b6fd5f8ace"
        );
    }
    #[test]
    fn special_pages_are_measured_without_their_contents() {
        let mut a = Vec::new();
        add_special(&mut a, SNP_SECRETS, PAGE_SECRETS);
        let mut b = a.clone();
        b[0].data[0] = 1;
        let v = vec![vmsa_page(&bsp_vmsa())];
        assert_eq!(launch_measurement(&a, &v), launch_measurement(&b, &v));
    }
    #[test]
    fn measurement_changes_with_content() {
        let mut p = Vec::new();
        add_normal(&mut p, 0x1000, &[0; 4096]);
        let v = vec![vmsa_page(&bsp_vmsa())];
        let a = launch_measurement(&p, &v);
        p[0].data[0] = 1;
        assert_ne!(a, launch_measurement(&p, &v));
    }
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD0QDbBc0T8m1BaeqCi\nGs30ddBtXsErRa5QX3eaeSYi11MZKeppqiBMm/fTnGxPP5KhZANiAASckeCIZYA6\nb96kAUX3v1H2Sk2iG+J23noMD403RN6PcnjsZWTIFa28YQYERl1BHB11uqFBzFG/\nOxpazENHn+p1pqw7y1frLk6qB4Gyi48pTb49fUOfkfqAPXA1xjy1tUg=\n-----END PRIVATE KEY-----\n";

    // The firmware enforces nothing until it verifies this signature over these bytes.
    #[test]
    fn id_block_signature_covers_the_digest_and_the_policy() {
        use p384::ecdsa::{signature::Verifier, VerifyingKey};
        let ld = [0x5au8; 48];
        let block = id_block(TEST_KEY, &ld, 7).unwrap();
        let IgvmDirectiveHeader::SnpIdBlock {
            ld: written,
            guest_svn,
            id_key_algorithm,
            id_key_signature,
            id_public_key,
            author_key_enabled,
            ..
        } = block.header
        else {
            panic!("not an ID block")
        };
        assert_eq!(written, ld);
        assert_eq!(guest_svn, 7);
        assert_eq!(id_key_algorithm, ID_KEY_ECDSA_P384);
        assert_eq!(author_key_enabled, 0);
        assert_eq!(id_public_key.curve, ID_CURVE_P384);

        let mut signed = [0u8; ID_BLOCK_LEN];
        signed[ID_BLOCK_LD..ID_BLOCK_LD + 48].copy_from_slice(&ld);
        signed[ID_BLOCK_VERSION_AT..ID_BLOCK_VERSION_AT + 4]
            .copy_from_slice(&ID_BLOCK_VERSION.to_le_bytes());
        signed[ID_BLOCK_SVN..ID_BLOCK_SVN + 4].copy_from_slice(&7u32.to_le_bytes());
        signed[ID_BLOCK_POLICY..ID_BLOCK_POLICY + 8]
            .copy_from_slice(&SNP_GUEST_POLICY.to_le_bytes());
        let point = p384::EncodedPoint::from_affine_coordinates(
            &be48(&id_public_key.qx).into(),
            &be48(&id_public_key.qy).into(),
            false,
        );
        let verifying = VerifyingKey::from_encoded_point(&point).unwrap();
        let signature = Signature::from_scalars(
            be48(&id_key_signature.r_comp),
            be48(&id_key_signature.s_comp),
        )
        .unwrap();
        verifying.verify(&signed, &signature).unwrap();
        // A block signed for a different policy must not verify against ours.
        signed[ID_BLOCK_POLICY] ^= 1;
        assert!(verifying.verify(&signed, &signature).is_err());
    }

    fn be48(le: &[u8; ECDSA_COMPONENT_LEN]) -> [u8; 48] {
        let mut v = [0u8; 48];
        for (at, byte) in le[..48].iter().rev().enumerate() {
            v[at] = *byte;
        }
        v
    }

    // RFC 6979 signing keeps a signed image byte-identical across builds.
    #[test]
    fn signing_is_deterministic() {
        let a = id_block(TEST_KEY, &[1; 48], 0).unwrap();
        let b = id_block(TEST_KEY, &[1; 48], 0).unwrap();
        assert_eq!(a.key_digest, b.key_digest);
        assert_eq!(format!("{:?}", a.header), format!("{:?}", b.header));
    }

    #[test]
    fn the_launch_digest_covers_one_vmsa_per_processor() {
        let mut pages = Vec::new();
        add_normal(&mut pages, 0x1000, &[0; PAGE as usize]);
        let bsp = vmsa_page(&bsp_vmsa());
        let ap = vmsa_page(&ap_vmsa());

        let one = launch_measurement(&pages, std::slice::from_ref(&bsp));
        let two = launch_measurement(&pages, &[bsp.clone(), ap.clone()]);
        let three = launch_measurement(&pages, &[bsp.clone(), ap.clone(), ap.clone()]);
        // Adding a processor adds a measured VMSA, so the digest has to move.
        assert_ne!(one, two);
        assert_ne!(two, three);
        // And the order is vp index order, not an unordered set.
        assert_ne!(two, launch_measurement(&pages, &[ap, bsp]));
    }

    /// The pages an image loads no longer depend on the processor count: the
    /// MADT that did is written by the shim from an unmeasured parameter. The
    /// save areas still do, one per processor, so the launch digest moves with
    /// --vcpus however the tables are built.
    #[test]
    fn the_processor_count_leaves_the_loaded_pages_alone() {
        let dir = tempdir().unwrap();
        let (k, i) = (dir.path().join("bzImage"), dir.path().join("initrd"));
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        let image = |cpus: u32| {
            let out = dir.path().join(format!("out{cpus}.igvm"));
            let params = Params::snp(DEFAULT_RAM, cpus, DEFAULT_CBIT, "").unwrap();
            build(&k, &i, &out, &params, None, None, 0).unwrap();
            let bytes = fs::read(&out).unwrap();
            let parsed = IgvmFile::new_from_binary(&bytes, None).unwrap();
            let loaded: Vec<String> = parsed
                .directives()
                .iter()
                .filter_map(|d| match d {
                    IgvmDirectiveHeader::PageData { gpa, data, .. } => {
                        Some(format!("{gpa:#x} {}", hex::encode(Sha384::digest(data))))
                    }
                    IgvmDirectiveHeader::ParameterInsert(p) => Some(format!("{:#x} -", p.gpa)),
                    _ => None,
                })
                .collect();
            (loaded, measure_snp(&bytes).unwrap())
        };
        let (loaded, digest) = image(2);
        for cpus in [4, 8] {
            let other = image(cpus);
            assert_eq!(loaded, other.0, "the loaded pages moved with --vcpus");
            assert_ne!(digest, other.1, "a processor was measured by nothing");
        }
    }

    #[test]
    fn an_snp_image_carries_one_vp_context_per_processor() {
        let dir = tempdir().unwrap();
        let (k, i) = (dir.path().join("bzImage"), dir.path().join("initrd"));
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        for cpus in [1u32, 2, 4] {
            let out = dir.path().join(format!("out{cpus}.igvm"));
            let params = Params::snp(DEFAULT_RAM, cpus, DEFAULT_CBIT, "").unwrap();
            build(&k, &i, &out, &params, None, None, 0).unwrap();
            let bytes = fs::read(&out).unwrap();
            let file = IgvmFile::new_from_binary(&bytes, None).unwrap();
            let mut indexes: Vec<u16> = file
                .directives()
                .iter()
                .filter_map(|d| match d {
                    IgvmDirectiveHeader::SnpVpContext { vp_index, gpa, .. } => {
                        // QEMU rejects any VP context that is not at this GPA.
                        assert_eq!(*gpa, SNP_VMSA);
                        Some(*vp_index)
                    }
                    _ => None,
                })
                .collect();
            indexes.sort_unstable();
            assert_eq!(indexes, (0..cpus as u16).collect::<Vec<_>>());
        }
    }

    /// The GHCB page is loaded and E820-reserved, and the shim never validates it itself.
    #[test]
    fn the_ghcb_page_is_placed_reserved_and_not_accepted() {
        let dir = tempdir().unwrap();
        let (k, i, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();
        let bytes = fs::read(&out).unwrap();
        let file = IgvmFile::new_from_binary(&bytes, None).unwrap();
        let pages: BTreeMap<u64, Vec<u8>> = file
            .directives()
            .iter()
            .filter_map(|d| match d {
                IgvmDirectiveHeader::PageData {
                    gpa,
                    data,
                    data_type,
                    ..
                } if *data_type == IgvmPageDataType::NORMAL => Some((*gpa, data.clone())),
                _ => None,
            })
            .collect();
        assert!(pages.contains_key(&SNP_GHCB));
        let (_, ranges) = crate::image::tests::shim_ranges(&pages[&SHIM_BASE], &params());
        assert!(!ranges.is_empty());
        assert!(!ranges
            .iter()
            .any(|(lo, hi)| *lo <= SNP_GHCB && SNP_GHCB < *hi));
        // The zero page's E820 map: entry count at 0x1e8, 20-byte entries from 0x2d0.
        // The shim writes the table at boot, so this is the map it will write.
        let (_, _, spans) = crate::image::tests::shim_data(&pages[&SHIM_BASE]);
        assert!(boot::read_e820(&pages[&ZERO_PAGE]).is_empty());
        let (top, host) = boot::host_regions(&params().extents());
        let e820 = boot::e820(&boot::merge(&spans, &host), top);
        let kind = e820
            .iter()
            .find(|(base, size, _)| *base <= SNP_GHCB && SNP_GHCB < base + size)
            .map(|(_, _, kind)| *kind);
        assert_eq!(kind, Some(RESERVED));
    }

    #[test]
    fn changing_any_measured_input_moves_the_measurement() {
        let dir = tempdir().unwrap();
        let kernel = dir.path().join("bzImage");
        let initramfs = dir.path().join("initrd");
        fs::write(&kernel, test_kernel()).unwrap();
        fs::write(&initramfs, vec![7u8; 100_000]).unwrap();
        let cmdline = "root=/dev/mapper/root roothash=aa11";

        let digest = |k: &Path, i: &Path, c: &str, vcpus: u32| -> String {
            let out = dir.path().join("out.igvm");
            let params = Params::snp(DEFAULT_RAM, vcpus, DEFAULT_CBIT, c).unwrap();
            build(k, i, &out, &params, None, None, 0).unwrap();
            let manifest = fs::read(format!("{}.manifest.json", out.display())).unwrap();
            let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
            manifest["expected_snp_measurement"]
                .as_str()
                .unwrap()
                .to_owned()
        };

        let base = digest(&kernel, &initramfs, cmdline, DEFAULT_VCPUS);
        assert_eq!(base, digest(&kernel, &initramfs, cmdline, DEFAULT_VCPUS));

        let other = dir.path().join("bzImage.other");
        let mut bytes = test_kernel();
        bytes[4096] ^= 1;
        fs::write(&other, bytes).unwrap();
        let moved = digest(&other, &initramfs, cmdline, DEFAULT_VCPUS);
        assert_ne!(
            base, moved,
            "one byte of the kernel left the measurement alone"
        );

        let other = dir.path().join("initrd.other");
        let mut bytes = vec![7u8; 100_000];
        bytes[1000] ^= 1;
        fs::write(&other, bytes).unwrap();
        let moved = digest(&kernel, &other, cmdline, DEFAULT_VCPUS);
        assert_ne!(
            base, moved,
            "one byte of the initramfs left the measurement alone"
        );

        let moved = digest(
            &kernel,
            &initramfs,
            "root=/dev/mapper/root roothash=ab11",
            DEFAULT_VCPUS,
        );
        assert_ne!(base, moved, "the command line left the measurement alone");

        let moved = digest(&kernel, &initramfs, cmdline, DEFAULT_VCPUS + 1);
        assert_ne!(
            base, moved,
            "the processor count left the measurement alone"
        );
    }

    /// The RAM a guest is given no longer reaches the digest: the E820 map and
    /// the accept list it decided are written by the shim, from a memory map
    /// the loader deposits after the measurement is closed. The file still
    /// states that RAM as required memory, because the loader has to make it
    /// private before the shim validates it, but nothing measured moves.
    #[test]
    fn the_guest_size_leaves_the_measurement_alone() {
        let dir = tempdir().unwrap();
        let (k, i) = (dir.path().join("bzImage"), dir.path().join("initrd"));
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        let digest = |ram| {
            let out = dir.path().join("out.igvm");
            let params = Params::snp(ram, DEFAULT_VCPUS, DEFAULT_CBIT, "").unwrap();
            build(&k, &i, &out, &params, None, None, 0).unwrap();
            measure_snp(&fs::read(&out).unwrap()).unwrap()
        };
        let base = digest(8 * GIB);
        for ram in [
            DEFAULT_RAM,
            2 * GIB,
            16 * GIB,
            64 * GIB,
            1024 * GIB,
            MAX_RAM,
        ] {
            assert_eq!(base, digest(ram), "{ram:#x} of RAM moved the digest");
        }
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
        build(&k, &i, &out, &params(), None, None, 0).unwrap();

        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(out.with_extension("igvm.manifest.json")).unwrap())
                .unwrap();
        let published = manifest["expected_snp_measurement"].as_str().unwrap();
        let recomputed = hex::encode(measure_snp(&fs::read(&out).unwrap()).unwrap());
        assert_eq!(published, recomputed);
    }

    #[test]
    fn measure_refuses_an_image_whose_pages_were_reordered() {
        let dir = tempdir().unwrap();
        let (k, i, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();

        let parsed = IgvmFile::new_from_binary(&fs::read(&out).unwrap(), None).unwrap();
        let mut directives = parsed.directives().to_vec();
        let pages: Vec<usize> = directives
            .iter()
            .enumerate()
            .filter(|(_, d)| matches!(d, IgvmDirectiveHeader::PageData { .. }))
            .map(|(n, _)| n)
            .collect();
        directives.swap(pages[0], pages[1]);
        let shuffled = IgvmFile::new(
            IgvmRevision::V1,
            vec![IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: COMPAT,
                    highest_vtl: 0,
                    platform_type: IgvmPlatformType::SEV_SNP,
                    platform_version: 1,
                    shared_gpa_boundary: 0,
                },
            )],
            vec![],
            directives,
        )
        .unwrap();
        let mut bytes = Vec::new();
        shuffled.serialize(&mut bytes).unwrap();

        let err = measure_snp(&bytes).unwrap_err();
        assert!(err.contains("overlap"), "unexpected error: {err}");
    }

    /// The loader imports the whole parameter area, and imports it where the
    /// file says: a file that widens the area, or states the insert after page
    /// data, loads in an order this digest does not describe.
    #[test]
    fn measure_refuses_a_parameter_area_it_does_not_model() {
        let dir = tempdir().unwrap();
        let (k, i, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();
        let parsed = IgvmFile::new_from_binary(&fs::read(&out).unwrap(), None).unwrap();

        let measure = |directives: Vec<IgvmDirectiveHeader>| {
            let file = IgvmFile::new(
                IgvmRevision::V1,
                vec![IgvmPlatformHeader::SupportedPlatform(
                    IGVM_VHS_SUPPORTED_PLATFORM {
                        compatibility_mask: COMPAT,
                        highest_vtl: 0,
                        platform_type: IgvmPlatformType::SEV_SNP,
                        platform_version: 1,
                        shared_gpa_boundary: 0,
                    },
                )],
                vec![],
                directives,
            )
            .unwrap();
            let mut bytes = Vec::new();
            file.serialize(&mut bytes).unwrap();
            measure_snp(&bytes)
        };

        let mut widened = parsed.directives().to_vec();
        let area = widened
            .iter()
            .position(|d| matches!(d, IgvmDirectiveHeader::ParameterArea { .. }))
            .unwrap();
        widened[area] = IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: 2 * PAGE,
            parameter_area_index: PARAM_AREA,
            initial_data: Vec::new(),
        };
        assert!(
            measure(widened).is_err(),
            "a two-page area was measured as one"
        );

        let mut late = parsed.directives().to_vec();
        let insert = late
            .iter()
            .position(|d| matches!(d, IgvmDirectiveHeader::ParameterInsert(_)))
            .unwrap();
        let moved = late.remove(insert);
        let after = late
            .iter()
            .position(|d| matches!(d, IgvmDirectiveHeader::PageData { .. }))
            .unwrap();
        late.insert(after + 1, moved);
        let err = measure(late).unwrap_err();
        assert!(err.contains("after page data"), "unexpected error: {err}");
    }

    /// One save area per processor, numbered from zero. Anything else describes
    /// a machine no firmware will launch.
    #[test]
    fn measure_refuses_duplicate_processor_indices() {
        let dir = tempdir().unwrap();
        let (k, i, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();

        let parsed = IgvmFile::new_from_binary(&fs::read(&out).unwrap(), None).unwrap();
        let directives: Vec<IgvmDirectiveHeader> = parsed
            .directives()
            .iter()
            .map(|d| match d {
                IgvmDirectiveHeader::SnpVpContext {
                    gpa,
                    compatibility_mask,
                    vmsa,
                    ..
                } => IgvmDirectiveHeader::SnpVpContext {
                    gpa: *gpa,
                    compatibility_mask: *compatibility_mask,
                    vp_index: 0,
                    vmsa: vmsa.clone(),
                },
                other => other.clone(),
            })
            .collect();
        let file = IgvmFile::new(
            IgvmRevision::V1,
            vec![IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: COMPAT,
                    highest_vtl: 0,
                    platform_type: IgvmPlatformType::SEV_SNP,
                    platform_version: 1,
                    shared_gpa_boundary: 0,
                },
            )],
            vec![],
            directives,
        )
        .unwrap();
        let mut bytes = Vec::new();
        file.serialize(&mut bytes).unwrap();

        let err = measure_snp(&bytes).unwrap_err();
        assert!(err.contains("expected 0.."), "unexpected error: {err}");
    }

    #[test]
    fn builds_reproducible_parseable_snp_images() {
        let dir = tempdir().unwrap();
        let (k, i, out) = (
            dir.path().join("bzImage"),
            dir.path().join("initrd"),
            dir.path().join("out.igvm"),
        );
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 100_000]).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();
        let one = fs::read(&out).unwrap();
        build(&k, &i, &out, &params(), None, None, 0).unwrap();
        assert_eq!(one, fs::read(&out).unwrap());
    }

    /// An SVN travels in the ID block or not at all, so accepting one without
    /// a key would publish a number the firmware never reports.
    #[test]
    fn an_unsigned_image_refuses_a_nonzero_guest_svn() {
        let dir = tempdir().unwrap();
        let (k, i) = (dir.path().join("bzImage"), dir.path().join("initrd"));
        fs::write(&k, test_kernel()).unwrap();
        fs::write(&i, vec![7u8; 1000]).unwrap();
        let out = dir.path().join("o.igvm");
        let err = build(&k, &i, &out, &params(), None, None, 3).unwrap_err();
        assert!(err.contains("--guest-svn needs --id-key"), "{err}");
        // Zero is what an unsigned launch reports, so it stays allowed.
        build(&k, &i, &out, &params(), None, None, 0).unwrap();
    }

    /// The manifest describes the image. What the machine happens to be is the
    /// verifier's platform policy, and asserting it from a build artifact
    /// would be asserting something this build cannot observe.
    #[test]
    fn the_launch_block_states_nothing_the_host_chooses() {
        let r = snp_launch(&[0u8; 48], zeros(32), 0, None);
        for host_chosen in [
            "platform_info_smt_en",
            "platform_info_rapl_dis",
            "platform_info_ciphertext_hiding_en",
            "signer_info_mask_chip_key",
            "reported_tcb",
            "vmpl",
            "family_id",
            "image_id",
            "author_key_digest",
        ] {
            assert!(!r.contains_key(host_chosen), "{host_chosen} is the host's");
        }
        // An exact set, so a newly added host field fails even though no
        // denylist names it.
        assert_eq!(
            r.keys().copied().collect::<Vec<_>>(),
            [
                "guest_svn",
                "host_data",
                "id_key_digest",
                "measurement",
                "policy"
            ]
        );
        // What is left is what a different image would change.
        assert_eq!(r["measurement"], zeros(48));
        assert_eq!(r["policy"], format!("0x{SNP_GUEST_POLICY:016x}"));
        assert_eq!(r["host_data"], zeros(32));
        assert_eq!(r["guest_svn"], "0");
        // Zero here says the firmware enforced no digest at launch.
        assert_eq!(r["id_key_digest"], zeros(48));
        let signed = snp_launch(&[0u8; 48], zeros(32), 0, Some([7u8; 48]));
        assert_eq!(signed["id_key_digest"], hex::encode([7u8; 48]));
    }
}

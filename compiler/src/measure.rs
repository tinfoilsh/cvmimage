//! Recomputing a launch digest from a finished image, so a published
//! measurement can be checked against the file shipped beside it without
//! reproducing the build. It runs the same digest code `build` ran.
//!
//! An honest digest of a malicious image still matches; that is what keeping
//! `firmware/` small enough to read is for.

use crate::{image, snp};
use igvm::{IgvmFile, IgvmPlatformHeader};
use igvm_defs::IgvmPlatformType;
use std::{fs, path::Path};

pub struct Measured {
    pub platform: &'static str,
    pub field: &'static str,
    pub measurement: [u8; 48],
}

/// The platform comes from the file, not a flag: measuring as the wrong one
/// would produce a plausible digest no hardware will report.
pub fn measure(path: &Path) -> Result<Measured, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let file =
        IgvmFile::new_from_binary(&bytes, None).map_err(|e| format!("read back IGVM: {e}"))?;

    let platforms: Vec<IgvmPlatformType> = file
        .platforms()
        .iter()
        .map(|p| match p {
            IgvmPlatformHeader::SupportedPlatform(p) => p.platform_type,
        })
        .collect();
    match platforms.as_slice() {
        [IgvmPlatformType::TDX] => Ok(Measured {
            platform: "tdx",
            field: "expected_mrtd",
            measurement: image::measure_tdx(&bytes)?,
        }),
        [IgvmPlatformType::SEV_SNP] => Ok(Measured {
            platform: "sev-snp",
            field: "expected_snp_measurement",
            measurement: snp::measure_snp(&bytes)?,
        }),
        // One file, one platform: a single digest cannot describe both.
        [only] => Err(format!(
            "IGVM file is for platform {only:?}, which has no launch digest this tool computes"
        )),
        other => Err(format!(
            "IGVM file declares {} platforms, expected exactly one",
            other.len()
        )),
    }
}

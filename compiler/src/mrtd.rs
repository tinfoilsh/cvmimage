use sha2::{Digest, Sha384};
use tinfoil_firmware::layout::PAGE;

// The digest of one TDH.MEM.PAGE.ADD per page and one TDH.MR.EXTEND per chunk of it.
const MR_RECORD_LEN: usize = 128;
const MR_GPA: usize = 16;
const MR_EXTEND_CHUNK: usize = 256;

pub fn calculate(pages: &[(u64, Vec<u8>)]) -> [u8; 48] {
    let mut hash = Sha384::new();
    for (gpa, data) in pages {
        let mut add = [0u8; MR_RECORD_LEN];
        add[..12].copy_from_slice(b"MEM.PAGE.ADD");
        add[MR_GPA..MR_GPA + 8].copy_from_slice(&gpa.to_le_bytes());
        hash.update(add);
        for offset in (0..PAGE as usize).step_by(MR_EXTEND_CHUNK) {
            let mut extend = [0u8; MR_RECORD_LEN];
            extend[..9].copy_from_slice(b"MR.EXTEND");
            extend[MR_GPA..MR_GPA + 8].copy_from_slice(&(gpa + offset as u64).to_le_bytes());
            hash.update(extend);
            hash.update(&data[offset..offset + MR_EXTEND_CHUNK]);
        }
    }
    hash.finalize().into()
}

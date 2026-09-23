mod image;
mod measure;
mod mrtd;
mod snp;

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tinfoil_firmware::layout::{Params, DEFAULT_CBIT, DEFAULT_RAM, DEFAULT_VCPUS};

#[derive(Parser)]
#[command(
    name = "cvmc",
    version,
    about = "Compile the Tinfoil firmware, a kernel and an initramfs into a measured CVM image"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, ValueEnum)]
enum Platform {
    /// Intel Trust Domain Extensions.
    Tdx,
    /// AMD Secure Encrypted Virtualization with Secure Nested Paging.
    Snp,
}

#[derive(Args)]
struct Common {
    #[arg(long)]
    kernel: PathBuf,
    #[arg(long)]
    initramfs: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Guest RAM the host must match, in 0x hex or with a K/M/G suffix.
    #[arg(long, default_value_t = DEFAULT_RAM, value_parser = parse_size)]
    ram: u64,
    /// Linux command line, measured whole, with `no5lvl` always appended.
    #[arg(long, default_value = "", hide_default_value = true)]
    cmdline: String,
    /// Processor count, which the measured MADT advertises. SNP additionally
    /// measures one VMSA per processor, so this changes the launch digest.
    #[arg(long, default_value_t = DEFAULT_VCPUS)]
    vcpus: u32,
    /// MRCONFIGID (TDX, 48 bytes) or HOST_DATA (SNP, 32 bytes) the host must
    /// pass, hex-encoded.
    #[arg(long)]
    config_hash: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Compile a measured IGVM image.
    Build {
        /// Which platform the image is measured for.
        #[arg(long, value_enum)]
        platform: Platform,
        #[command(flatten)]
        common: Common,
        /// SEV-SNP only: encryption bit the identity map is built around.
        #[arg(long, default_value_t = DEFAULT_CBIT)]
        cbit: u8,
        /// SEV-SNP only: PKCS#8 PEM P-384 key that signs the ID block the
        /// firmware enforces.
        #[arg(long)]
        id_key: Option<PathBuf>,
        /// SEV-SNP only: anti-rollback version placed in the signed ID block.
        #[arg(long, default_value_t = 0)]
        guest_svn: u32,
    },
    /// Recompute the launch digest of an IGVM image, to check it against a
    /// published measurement without rebuilding it.
    Measure {
        /// The IGVM file to read.
        image: PathBuf,
    },
}

fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, scale) = match text.as_bytes().last() {
        Some(b'K' | b'k') => (&text[..text.len() - 1], 1 << 10),
        Some(b'M' | b'm') => (&text[..text.len() - 1], 1 << 20),
        Some(b'G' | b'g') => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => digits.parse(),
    };
    value
        .map_err(|e| e.to_string())?
        .checked_mul(scale)
        .ok_or_else(|| "size overflows".to_string())
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Build {
            platform: Platform::Tdx,
            common,
            cbit,
            id_key,
            guest_svn,
        } => {
            // Accepting and ignoring these would let a script ask for a
            // signed image, get an unsigned one, and exit zero.
            if id_key.is_some() || guest_svn != 0 || cbit != DEFAULT_CBIT {
                return Err(
                    "--id-key, --guest-svn and --cbit are SEV-SNP only; TDX measures no ID block"
                        .into(),
                );
            }
            let params = Params::tdx(common.ram, common.vcpus, &common.cmdline)?;
            image::build(
                &common.kernel,
                &common.initramfs,
                &common.output,
                &params,
                common.config_hash.as_deref(),
            )
        }
        Command::Build {
            platform: Platform::Snp,
            common,
            cbit,
            id_key,
            guest_svn,
        } => {
            let params = Params::snp(common.ram, common.vcpus, cbit, &common.cmdline)?;
            snp::build(
                &common.kernel,
                &common.initramfs,
                &common.output,
                &params,
                common.config_hash.as_deref(),
                id_key.as_deref(),
                guest_svn,
            )
        }
        Command::Measure { image } => {
            let m = measure::measure(&image)?;
            println!("platform: {}", m.platform);
            println!("{}: {}", m.field, hex::encode(m.measurement));
            Ok(())
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

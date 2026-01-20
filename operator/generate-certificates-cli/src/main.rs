use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

use anyhow::{Context, Ok};
use clap::Parser;
use inquire::Confirm;
use log::info;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path where the `cert.pem` and `key.pem` files will be created
    #[arg(long)]
    cert_directory_path: PathBuf,

    /// Overwrite existing files without prompting
    #[arg(short, long, default_value_t = false)]
    force: bool,
}

// Given a string representing a path to the certificates directory
// it looks for a cert.pem and key.pem files inside that directory,
// representing a public, and private key pair in PKCS#8 format. If they are not present
// it will create them and save them on the filesystem.
pub fn create_or_get_certificates(certificate_dir: PathBuf, force: bool) -> anyhow::Result<()> {
    // Step 1. Generate Self Signed Certificates, if not already presents
    let cert_path = certificate_dir.join("cert.pem");
    let key_path = certificate_dir.join("key.pem");

    if !certificate_dir.is_dir() {
        info!(
            "Certificate directory {} not found, creating it now",
            certificate_dir.display()
        );

        fs::create_dir(&certificate_dir).context(format!(
            "Error creating certificates directory {}",
            certificate_dir.display()
        ))?;
    }

    let mut confirm = true;
    if !force && (cert_path.exists() || key_path.exists()) {
        confirm = Confirm::new("The selected directory contains already a `cert.pem` or `key.pem` file. If you continue they will be overwritten.")
            .with_default(false)
            .with_help_message(
                "Continue?",
            )
            .prompt()?;
    }
    if confirm {
        let subject_alt_names = vec!["MITHRILOS K3S BOOTSTRAP OPERATOR CERT".to_string()];
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names)
            .context("Error while generating self signed ephemeral cert")?;
        if !certificate_dir.is_dir() {
            fs::create_dir(&certificate_dir)
                .context(format!("Error creating {:?} directory", certificate_dir))?;
        }

        let key_pem = signing_key.serialize_pem();
        let mut private_key = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // -rw-------
            .open(key_path)
            .context("Error opening `key.pem` for writing")?;
        private_key
            .write_all(key_pem.as_bytes())
            .context("Error writing private key to `key.pem`")?;

        let cert_pem = cert.pem();
        let mut certificate = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644) // -rw-r--r--, the default, but set explicitly
            .open(cert_path)
            .context("Error opening `key.pem` for writing")?;
        certificate
            .write_all(cert_pem.as_bytes())
            .context("Error writing certificate to `cert.pem`")?;
        info!("Public and Private key pair generated successfully");
    } else {
        info!("Skipping certificate creation.");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "generate_certificates_cli=debug,provisioning_structs=debug".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    create_or_get_certificates(args.cert_directory_path, args.force)?;

    Ok(())
}

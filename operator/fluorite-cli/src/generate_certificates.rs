use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

use anyhow::{Context, Ok};
use inquire::Confirm;
use log::info;
use rcgen::{CertifiedKey, generate_simple_self_signed};

/// Given a path to the certificates directory, looks for cert.pem and key.pem files
/// inside that directory, representing a public and private key pair in PKCS#8 format.
/// If they are not present, it will create them and save them on the filesystem.
pub fn create_or_get_certificates(certificate_dir: PathBuf, force: bool) -> anyhow::Result<()> {
    // Step 1. Generate Self Signed Certificates, if not already present
    let cert_path = certificate_dir.join("cert.pem");
    let key_path = certificate_dir.join("key.pem");

    if !certificate_dir.is_dir() {
        info!(
            "Certificate directory {} not found, creating it now",
            certificate_dir.display()
        );

        fs::create_dir_all(&certificate_dir).context(format!(
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
            .open(&key_path)
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
            .open(&cert_path)
            .context("Error opening `cert.pem` for writing")?;
        certificate
            .write_all(cert_pem.as_bytes())
            .context("Error writing certificate to `cert.pem`")?;
        info!("Public and Private key pair generated successfully");
        info!("Certificate saved to: {}", cert_path.display());
        info!("Private key saved to: {}", key_path.display());
    } else {
        info!("Skipping certificate creation.");
    }

    Ok(())
}

use anyhow::{Context as _, anyhow, bail};
use rustls_pemfile::Item;
use rustls_pki_types::CertificateDer;

pub(crate) fn pem_to_der(pem_cert: &str) -> anyhow::Result<CertificateDer<'static>> {
    let (pem_item, _remaining) = rustls_pemfile::read_one_from_slice(pem_cert.as_bytes())
        .map_err(|e| anyhow!("{:?}", e))
        .context("Could not read a PEM file")?
        .context("No PEM item")?;

    let Item::X509Certificate(cert_der) = pem_item else {
        bail!("Pem file provided is not a X509 Certificate");
    };
    Ok(cert_der)
}

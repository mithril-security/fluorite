use crate::GCP_AK_ROOT_CA_DER;
use anyhow::bail;
use anyhow::Context as _;
use const_oid::ObjectIdentifier;
use fn_error_context::context;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::UnixTime;
use webpki::anchor_from_trusted_cert;
use webpki::EndEntityCert;
use webpki::KeyUsage;
use x509_parser::prelude::FromDer;

use x509_parser::prelude::X509Certificate;

const TCG_KP_EK_CERTIFICATE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.1");

#[context("Invalid GCP AK certificate chain")]
pub fn validate_ak_chain<'a>(
    cert_chain: &'a [impl AsRef<[u8]>],
    now: UnixTime,
) -> anyhow::Result<CertificateDer<'a>> {
    if cert_chain.is_empty() {
        bail!("Certificate chain is empty")
    }

    let gcp_ak_root_ca_der = CertificateDer::from(GCP_AK_ROOT_CA_DER);
    let trust_anchor = anchor_from_trusted_cert(&gcp_ak_root_ca_der)?;

    let leaf_cert_der = CertificateDer::from(cert_chain[0].as_ref());
    let leaf_cert: EndEntityCert<'_> = EndEntityCert::try_from(&leaf_cert_der)?;

    let intermediate_certs: Vec<CertificateDer> = cert_chain[1..cert_chain.len() - 1]
        .iter()
        .map(|cert_der| CertificateDer::from(cert_der.as_ref()))
        .collect();

    leaf_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[trust_anchor],
        &intermediate_certs,
        now,
        KeyUsage::required_if_present(TCG_KP_EK_CERTIFICATE_OID.as_ref()),
        None,
        None,
    )?;

    let (&[], cert) = X509Certificate::from_der(cert_chain[0].as_ref())? else {
        bail!("Bad leaf certificate. Could not parse it with X509Certificate::from_der");
    };

    if !cert
        .key_usage()?
        .context("No Key Usage found in leaf certificate")?
        .value
        .digital_signature()
    {
        bail!("Bad Key Usage in AK certificate : Digital Signature not allowed")
    }
    Ok(leaf_cert_der)
}

#[test]
fn test_validate_gcp_ak_chain() -> anyhow::Result<()> {
    use std::fs;
    let leaf_cert_der = fs::read("test_data/cert_chain/ak_cert_ecc.crt")?;
    let intermediate_cert_der = fs::read("test_data/cert_chain/ak_intermediate_ca.crt")?;
    let root_cert_der = fs::read("test_data/cert_chain/gcp_ak_root_ca.crt")?;
    let cert_chain = [
        &leaf_cert_der[..],
        &intermediate_cert_der[..],
        &root_cert_der[..],
    ];
    let _ = validate_ak_chain(&cert_chain[..], UnixTime::now())?;
    Ok(())
}

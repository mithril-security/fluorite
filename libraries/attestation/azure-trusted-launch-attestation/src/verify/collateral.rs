use fn_error_context::context;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::EndEntityCert;
use webpki::{KeyUsage, anchor_from_trusted_cert};

use anyhow::{Result, bail};

use const_oid::ObjectIdentifier;

use crate::AZURE_VTPM_ROOT_CA_PEM;

pub const TCG_KP_AIK_CERTIFICATE_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.8.3");

#[context("Invalid Azure AK certificate chain")]
pub fn validate_ak_cert_chain<'a>(
    cert_chain: &'a [impl AsRef<[u8]>],
    now: UnixTime,
) -> anyhow::Result<CertificateDer<'a>> {
    // use pem::Pem;
    // let cert_chain_pem = pem::encode_many(
    //     &cert_chain
    //         .iter()
    //         .map(|cert_der| Pem::new("CERTIFICATE", cert_der.as_ref().to_vec()))
    //         .collect::<Vec<_>>(),
    // );
    // log::info!("{}", cert_chain_pem);
    if cert_chain.is_empty() {
        bail!("Certificate chain is empty")
    }

    let root_ca = CertificateDer::from_pem_slice(AZURE_VTPM_ROOT_CA_PEM)?;
    let trust_anchor = anchor_from_trusted_cert(&root_ca)?;

    let leaf_cert_der = CertificateDer::from(cert_chain[0].as_ref());
    let leaf_cert = EndEntityCert::try_from(&leaf_cert_der)?;

    let intermediate_certs: Vec<CertificateDer> = cert_chain[1..cert_chain.len() - 1]
        .iter()
        .map(|cert_der| Ok(CertificateDer::from(cert_der.as_ref())))
        .collect::<Result<_>>()?;

    leaf_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[trust_anchor],
        &intermediate_certs,
        now,
        KeyUsage::required(TCG_KP_AIK_CERTIFICATE_OID.as_ref()),
        None,
        None,
    )?;
    Ok(leaf_cert_der)
}

#[cfg(test)]
mod test {
    use std::fs;

    use crate::TrustedLaunchVmAttestationDocument;

    use super::*;

    #[test]
    fn test_validate_ak_cert_chain_ok() -> anyhow::Result<()> {
        use std::fs;
        let doc: TrustedLaunchVmAttestationDocument = serde_json::from_slice(&fs::read(
            "test_data/azure_trusted_launch_vm_attestation_document.json",
        )?)?;
        println!("doc.ak_cert_chain: {:?}", doc.ak_cert_chain);
        let leaf_cert = validate_ak_cert_chain(&doc.ak_cert_chain, UnixTime::now())?;
        assert_eq!(&leaf_cert[..], doc.ak_cert_chain[0]);
        Ok(())
    }

    #[test]
    fn test_validate_ak_cert_chain_expired() -> anyhow::Result<()> {
        let doc: TrustedLaunchVmAttestationDocument = serde_json::from_slice(&fs::read(
            "test_data/azure_trusted_launch_vm_attestation_document_expired.json",
        )?)?;

        if !format!(
            "{:?}",
            validate_ak_cert_chain(&doc.ak_cert_chain, UnixTime::now())
                .unwrap_err()
                .root_cause()
        )
        .contains("CertExpired")
        {
            bail!("Cert chain validation should fail with CertExpired");
        }
        Ok(())
    }
}

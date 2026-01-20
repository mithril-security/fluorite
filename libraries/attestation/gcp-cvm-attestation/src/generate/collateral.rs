use crate::{AKCERT_NVINDEX_ECC, GCP_AK_ROOT_CA_DER};
use anyhow::{bail, Context as _};
use fn_error_context::context;
use x509_parser::{
    oid_registry,
    prelude::{FromDer as _, ParsedExtension, X509Certificate},
};

#[context("Could not read AK cert from the TPM")]
fn read_ak_cert_ecc(ctx: &mut tss_esapi::Context) -> anyhow::Result<Vec<u8>> {
    use tss_esapi::abstraction::nv;
    use tss_esapi::handles::NvIndexTpmHandle;
    use tss_esapi::interface_types::resource_handles::NvAuth;

    let nv_index = NvIndexTpmHandle::new(AKCERT_NVINDEX_ECC)?;

    let ak_cert =
        ctx.execute_with_nullauth_session(|ctx| nv::read_full(ctx, NvAuth::Owner, nv_index))?;

    log::info!("{:?}", ak_cert);
    Ok(ak_cert)
}

#[test]
#[ignore]
fn test_read_ak_cert_ecc() -> anyhow::Result<()> {
    use tpm_quote::generate::tpm_context;

    let mut ctx = tpm_context()?;
    let _ = read_ak_cert_ecc(&mut ctx)?;
    Ok(())
}

async fn fetch_issuing_certificate(cert_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (&[], cert) = X509Certificate::from_der(cert_der)? else {
        bail!("Bad certificate. Could not parse it with X509Certificate::from_der");
    };
    let ParsedExtension::AuthorityInfoAccess(authority_information_access) = cert
        .get_extension_unique(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)?
        .context("No AuthorityInfoAccess extension found")?
        .parsed_extension()
    else {
        bail!("Got bad extension type for AuthorityInfoAccess OID");
    };

    let binding = authority_information_access.as_hashmap();
    let ca_issuers: &[&x509_parser::prelude::GeneralName<'_>] = binding
        .get(&oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS)
        .context("No CA issuer found in AuthorityInfoAccess")?
        .as_slice();
    let &[&x509_parser::prelude::GeneralName::URI(ca_issuers_uri)] = ca_issuers else {
        bail!("Could not get CA URI from CA issuers");
    };

    let cert_as_bytes = reqwest::get(ca_issuers_uri)
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    Ok(cert_as_bytes.to_vec())
}

/// Retrieves the Attestation Key (AK) certificate chain of a GCE Confidential VM.
///  
/// Returns DER-encoded certificates, ordered from leaf to root.
/// This function should only be called on a GCE Confidential VM. It will fail on GCE Shielded VMs because
/// their vTPMs are not provisioned with AK certificate.
///  
/// # Errors
///
/// This function will return an error if:
///
/// - The AK certificate cannot be retrieved from the vTPM. This will happen if this function is erroneously called on a Shielded VM for instance.
/// - The intermediate or root CA certificates cannot be fetched. In that case check the CVM network connectivity.
/// - The root CA certificate does not match the expected GCP AK Root CA.
#[context("get_ak_cert_chain failed")]
pub async fn get_ak_cert_chain(ctx: &mut tss_esapi::Context) -> anyhow::Result<Vec<Vec<u8>>> {
    let leaf_cert_der = read_ak_cert_ecc(ctx)?;
    fetch_issuing_certificates(leaf_cert_der).await
}

#[context("Could not fetch issuing certificates")]
pub async fn fetch_issuing_certificates(leaf_cert_der: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>> {
    let intermediate_cert_der = fetch_issuing_certificate(&leaf_cert_der)
        .await
        .context("Could not fetch the intermediate CA certificate")?;
    let root_cert_der = fetch_issuing_certificate(&intermediate_cert_der)
        .await
        .context("Could not fetch the Root CA certificate")?;

    if root_cert_der != GCP_AK_ROOT_CA_DER {
        bail!("Fetched Root CA differ from expected GCP AK Root CA");
    }
    Ok(vec![leaf_cert_der, intermediate_cert_der, root_cert_der])
}

#[cfg(test)]
#[tokio::test]
async fn test_fetch_intermediate_certs_given_leaf() -> anyhow::Result<()> {
    let leaf_cert_der = std::fs::read("test_data/cert_chain/ak_cert_ecc.crt")?;
    let _ = fetch_issuing_certificates(leaf_cert_der).await?;
    Ok(())
}

// #[cfg(test)]
// #[tokio::test]
// async fn test_fetch_intermediate_certs_error() -> anyhow::Result<()> {
//     let leaf_cert_der = fs::read("test_data/cert_chain/ak_intermediate_ca.crt")?;
//     let _ = fetch_issuing_certificates(leaf_cert_der).await?;
//     Ok(())
// }

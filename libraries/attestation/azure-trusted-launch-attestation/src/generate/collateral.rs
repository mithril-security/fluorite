use crate::{AZURE_VTPM_INTERMEDIATE_CA_PEM, AZURE_VTPM_ROOT_CA_PEM, VTPM_AK_CERT_NVINDEX};
use anyhow::{Context as _, bail};
use fn_error_context::context;
use rustls_pki_types::{CertificateDer, pem::PemObject};
use x509_parser::parse_x509_certificate;

#[context("Could not read AK cert from the TPM")]
fn read_ak_cert(ctx: &mut tss_esapi::Context) -> anyhow::Result<Vec<u8>> {
    use tss_esapi::abstraction::nv;
    use tss_esapi::handles::NvIndexTpmHandle;
    use tss_esapi::interface_types::resource_handles::NvAuth;

    let nv_index = NvIndexTpmHandle::new(VTPM_AK_CERT_NVINDEX)?;

    let ak_cert =
        ctx.execute_with_nullauth_session(|ctx| nv::read_full(ctx, NvAuth::Owner, nv_index))?;

    log::info!("{:?}", ak_cert);
    Ok(ak_cert)
}

#[test]
#[ignore]
fn test_read_ak_cert() -> anyhow::Result<()> {
    use tpm_quote::generate::tpm_context;

    let mut ctx = tpm_context()?;
    let ak_cert = read_ak_cert(&mut ctx)?;
    println!("{:?}", &ak_cert);
    Ok(())
}

/// Retrieves the Attestation Key (AK) certificate chain of an Azure Trusted Launch VM.
///  
/// Returns DER-encoded certificates, ordered from leaf to root.
/// This function should only be called on a Azure Trusted Launch VM.
///
/// # Errors
///
/// This function will return an error if the AK certificate cannot be retrieved from the vTPM.
#[context("get_ak_cert_chain failed")]
pub fn get_ak_cert_chain(ctx: &mut tss_esapi::Context) -> anyhow::Result<Vec<Vec<u8>>> {
    let leaf_cert_der = read_ak_cert(ctx)?;
    let root_cert_der = &CertificateDer::from_pem_slice(AZURE_VTPM_ROOT_CA_PEM)?[..];

    let issuer_cn_leaf = parse_x509_certificate(&leaf_cert_der)?
        .1
        .issuer()
        .iter_common_name()
        .next()
        .context("Common Name of Issuer not found in the leaf certificate")?
        .as_str()
        .context("Common Name of Issuer could not be parsed to a string")?
        .to_string();

    let intermediate_cert_pem = match &issuer_cn_leaf[..] {
        "Global Virtual TPM CA - 01" => AZURE_VTPM_INTERMEDIATE_CA_PEM[0],
        "Global Virtual TPM CA - 03" => AZURE_VTPM_INTERMEDIATE_CA_PEM[1],
        _ => {
            bail!("No intermediate certificate found that matches the leaf certificate issuer");
        }
    };

    let intermediate_cert_der = CertificateDer::from_pem_slice(intermediate_cert_pem)?;

    return Ok(vec![
        leaf_cert_der,
        intermediate_cert_der.to_vec(),
        root_cert_der.to_vec(),
    ]);
}

#[test]
#[ignore]
fn test_get_ak_cert_chain() -> anyhow::Result<()> {
    use tpm_quote::generate::tpm_context;

    let mut ctx = tpm_context()?;
    let ak_cert_chain = get_ak_cert_chain(&mut ctx)?;
    insta::assert_debug_snapshot!(ak_cert_chain[1]);
    insta::assert_debug_snapshot!(ak_cert_chain[2]);
    println!("{:?}", ak_cert_chain);
    Ok(())
}

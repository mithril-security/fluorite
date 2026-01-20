use crate::{QEMU_VTPM_INTERMEDIATE_CA_PEM, QEMU_VTPM_ROOT_CA_PEM, VTPM_AK_CERT_NVINDEX};
use fn_error_context::context;
use rustls_pki_types::{CertificateDer, pem::PemObject};

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

/// Retrieves the Attestation Key (AK) certificate chain of an QEMU VM.
///  
/// Returns DER-encoded certificates, ordered from leaf to root.
/// This function should only be called on a QEMU VM.
///
/// # Errors
///
/// This function will return an error if the AK certificate cannot be retrieved from the vTPM.
#[context("get_ak_cert_chain failed")]
pub fn get_ak_cert_chain(ctx: &mut tss_esapi::Context) -> anyhow::Result<Vec<Vec<u8>>> {
    let leaf_cert_der = read_ak_cert(ctx)?;
    let root_cert_der = &CertificateDer::from_pem_slice(QEMU_VTPM_ROOT_CA_PEM)?[..];
    let intermediate_cert_der = &CertificateDer::from_pem_slice(QEMU_VTPM_INTERMEDIATE_CA_PEM)?[..];
    Ok(vec![
        leaf_cert_der,
        intermediate_cert_der.to_vec(),
        root_cert_der.to_vec(),
    ])
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

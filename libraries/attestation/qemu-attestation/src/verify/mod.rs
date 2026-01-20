use crate::QEMUVmAttestationDocument;
use attestation::VerifyAttestationDocument;
use fn_error_context::context;
use rustls_pki_types::UnixTime;
use sha2::Sha256;
use tpm_quote::{common::SanitizedPcrData, verify::AttestationKey};

impl VerifyAttestationDocument for QEMUVmAttestationDocument {
    #[context("QEMUVmAttestationDocument::verify failed")]
    fn verify(&self, _now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        let QEMUVmAttestationDocument {
            quote,
            ak_cert_chain: _,
        } = self;
        let ak = QEMUAttestationKey();
        let pcr_data = ak.verify_quote(quote)?;

        Ok(pcr_data)
    }
}

struct QEMUAttestationKey();

impl AttestationKey for QEMUAttestationKey {
    type Digest = Sha256;

    #[context("QEMUAttestationKey::verify_signature failed")]
    fn verify_signature(&self, _message: &[u8], _signature: &[u8]) -> anyhow::Result<()> {
        // Do nothing and return OK(())
        Ok(())
    }
}

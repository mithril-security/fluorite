pub mod configtsm;

use crate::{generate_nonce, request_vcek_cert, SvsmVtpmAttestationDocument, VTPM_AK_HANDLE};
use async_trait::async_trait;
use attestation::AsyncGenerateAttestationDocument;
use configtsm::get_attestion_report;
use fn_error_context::context;
use sev::{
    certs::snp::{self, ca, Verifiable},
    Generation,
};
use tpm_quote::generate::{tpm_context, AttestationKeyHandle};
use tss_esapi::{handles::TpmHandle, structures::PcrSelectionList};
pub struct SvsmVtpmAttestationDocumentGenerator(tss_esapi::Context);

impl SvsmVtpmAttestationDocumentGenerator {
    #[context("Failed to create a TPM context")]
    pub fn new_with_default() -> anyhow::Result<Self> {
        Ok(Self::new_with_tpm_ctx(tpm_context()?))
    }

    pub fn new_with_tpm_ctx(tpm_ctx: tss_esapi::Context) -> Self {
        Self(tpm_ctx)
    }
}

#[async_trait]
impl AsyncGenerateAttestationDocument for SvsmVtpmAttestationDocumentGenerator {
    type AttestationDocument = SvsmVtpmAttestationDocument;

    /// Produce an attestation document attesting to the selected PCR list
    ///
    /// This function should only be called on SVSM with vTPM Confidential VM.
    async fn generate_attestation_document(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
    ) -> anyhow::Result<Self::AttestationDocument> {
        let mut ak_handle = AttestationKeyHandle::from_tpm_handle(
            &mut self.0,
            TpmHandle::try_from(VTPM_AK_HANDLE)?,
        )?;

        // Signing and generating the quote
        let quote: tpm_quote::common::Quote = ak_handle.quote(pcr_selection_list)?;

        let nonce: [u8; 64] = generate_nonce()?;
        let (attestation_report, ak_pub_key) = get_attestion_report(&nonce)?;

        let chip_id = attestation_report.chip_id;
        let reported_tcb = attestation_report.reported_tcb;
        let host_generation = Generation::identify_host_generation()?;

        let ca_chain = ca::Chain::from(host_generation);
        let _ = ca_chain.verify()?;

        let vcek_leaf_cert = request_vcek_cert(host_generation, *chip_id, reported_tcb).await?;

        let chain = snp::Chain {
            ca: ca_chain,
            vek: vcek_leaf_cert,
        };

        let _ = chain.verify()?;

        Ok(SvsmVtpmAttestationDocument {
            quote,
            attestation_report,
            sev_cert_chain: chain.try_into()?,
            ak_pub_key: ak_pub_key,
            nonce: nonce.to_vec(),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::SvsmVtpmAttestationDocumentGenerator;
    use attestation::{AsyncGenerateAttestationDocument as _, VerifyAttestationDocument};
    use rustls_pki_types::UnixTime;
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::structures::{PcrSelectionList, PcrSlot};

    const ALL_SLOTS: &[PcrSlot; 24] = &[
        PcrSlot::Slot0,
        PcrSlot::Slot1,
        PcrSlot::Slot2,
        PcrSlot::Slot3,
        PcrSlot::Slot4,
        PcrSlot::Slot5,
        PcrSlot::Slot6,
        PcrSlot::Slot7,
        PcrSlot::Slot8,
        PcrSlot::Slot9,
        PcrSlot::Slot10,
        PcrSlot::Slot11,
        PcrSlot::Slot12,
        PcrSlot::Slot13,
        PcrSlot::Slot14,
        PcrSlot::Slot15,
        PcrSlot::Slot16,
        PcrSlot::Slot17,
        PcrSlot::Slot18,
        PcrSlot::Slot19,
        PcrSlot::Slot20,
        PcrSlot::Slot21,
        PcrSlot::Slot22,
        PcrSlot::Slot23,
    ];

    #[tokio::test]
    #[ignore]
    async fn test_svsm_confidential_vm_attestation_document() -> anyhow::Result<()> {
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
            .build()?;

        let doc = SvsmVtpmAttestationDocumentGenerator::new_with_default()?
            .generate_attestation_document(&pcr_selection_list)
            .await?;

        let _pcr = doc.verify(UnixTime::now())?;

        Ok(())
    }
}

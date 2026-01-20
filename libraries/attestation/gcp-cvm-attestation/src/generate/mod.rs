mod collateral;

use crate::{CvmAttestationDocument, AKTEMPLATE_NVINDEX_ECC};
use async_trait::async_trait;
use attestation::AsyncGenerateAttestationDocument;
use fn_error_context::context;
use tpm_quote::generate::{tpm_context, AttestationKeyHandle};
use tss_esapi::structures::PcrSelectionList;

pub struct CvmAttestationDocumentGenerator(tss_esapi::Context);

impl CvmAttestationDocumentGenerator {
    #[context("Failed to create a TPM context")]
    pub fn new_with_default() -> anyhow::Result<Self> {
        Ok(Self::new_with_tpm_ctx(tpm_context()?))
    }

    pub fn new_with_tpm_ctx(tpm_ctx: tss_esapi::Context) -> Self {
        Self(tpm_ctx)
    }
}

#[async_trait]
impl AsyncGenerateAttestationDocument for CvmAttestationDocumentGenerator {
    type AttestationDocument = CvmAttestationDocument;

    /// Produce an attestation document attesting to the selected PCR list
    ///
    /// This function should only be called on GCP Confidential VM.
    async fn generate_attestation_document(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
    ) -> anyhow::Result<Self::AttestationDocument> {
        let mut ak_handle = AttestationKeyHandle::create_from_template_at_nvindex(
            &mut self.0,
            AKTEMPLATE_NVINDEX_ECC.try_into()?,
        )?;

        let quote = ak_handle.quote(pcr_selection_list)?;

        let ak_cert_chain = collateral::get_ak_cert_chain(&mut self.0).await?;

        Ok(CvmAttestationDocument {
            quote,
            ak_cert_chain,
        })
    }
}
#[cfg(test)]
mod test {
    use crate::{CvmAttestationDocument, CvmAttestationDocumentGenerator};
    use attestation::AsyncGenerateAttestationDocument as _;
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
    async fn test_gcp_confidential_vm_attestation_document() -> anyhow::Result<()> {
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
            .build()?;

        let _ = CvmAttestationDocumentGenerator::new_with_default()?
            .generate_attestation_document(&pcr_selection_list)
            .await?;
        Ok(())
    }
}

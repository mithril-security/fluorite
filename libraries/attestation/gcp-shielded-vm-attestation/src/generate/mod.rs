//! Generation of GCP Shielded VM attestation documents
//!
//! This module provides functionality to generate attestation documents
//! on GCP Shielded VMs by:
//! 1. Fetching the notarizer endorsement from instance *user-data* (startup-script/metadata "notarizer_endorsement")
//! 2. Generating a vTPM quote

use crate::AKTEMPLATE_NVINDEX_ECC;
use crate::{NotarizeResponse, ShieldedVmAttestationDocument};
use anyhow::Context;
use async_trait::async_trait;
use attestation::AsyncGenerateAttestationDocument;
use fn_error_context::context;
use tpm_quote::generate::{tpm_context, AttestationKeyHandle};
use tss_esapi::handles::TpmHandle;
use tss_esapi::structures::PcrSelectionList;

/// GCP metadata server URL
const METADATA_SERVER_URL: &str = "http://metadata.google.internal/computeMetadata/v1";

const USERDATA_METADATA_KEY: &str = "user-data";

/// Generator for Shielded VM attestation documents
pub struct ShieldedVmAttestationDocumentGenerator {
    tpm_ctx: tss_esapi::Context,
    notarizer_endorsement: NotarizeResponse,
}

impl ShieldedVmAttestationDocumentGenerator {
    #[context("Failed to create a ShieldedVmAttestationDocumentGenerator")]
    pub async fn new_with_default() -> anyhow::Result<Self> {
        Ok(Self::new_with_tpm_ctx(tpm_context()?).await?)
    }

    pub async fn new_with_tpm_ctx(tpm_ctx: tss_esapi::Context) -> anyhow::Result<Self> {
        Ok(Self {
            tpm_ctx,
            notarizer_endorsement: Self::fetch_notarizer_endorsement().await?,
        })
    }

    /// Fetch the notarizer endorsement from `user-data` in instance metadata
    #[context("Failed to fetch notarizer endorsement from user-data in metadata")]
    async fn fetch_notarizer_endorsement() -> anyhow::Result<NotarizeResponse> {
        let client = reqwest::Client::new();

        let url = format!(
            "{}/instance/attributes/{}",
            METADATA_SERVER_URL, USERDATA_METADATA_KEY
        );
        log::info!("Fetching user-data from instance metadata: {}", url);

        let response = client
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .context("Failed to fetch user-data from metadata server")?;

        // The user-data value is a JSON string (see operator/gcp-vm-cli/main.py)
        let user_data_json = response
            .text()
            .await
            .context("Failed to read user-data text from metadata")?;

        // Parse as JSON and extract "notarizer_endorsement"
        let user_data_val: serde_json::Value =
            serde_json::from_str(&user_data_json).context("Failed to parse user-data as JSON")?;

        let notarizer_endorsement_val = user_data_val
            .get("notarizer_endorsement")
            .ok_or_else(|| anyhow::anyhow!("user-data did not contain notarizer_endorsement"))?;

        // Deserialize that field as NotarizeResponse
        let notarizer_endorsement: NotarizeResponse =
            serde_json::from_value(notarizer_endorsement_val.clone())
                .context("Failed to deserialize notarizer_endorsement from user-data")?;

        log::info!("Successfully fetched notarizer_endorsement from user-data in metadata");
        Ok(notarizer_endorsement)
    }
}

#[async_trait]
impl AsyncGenerateAttestationDocument for ShieldedVmAttestationDocumentGenerator {
    type AttestationDocument = ShieldedVmAttestationDocument;

    /// Generate an attestation document for this Shielded VM
    ///
    /// This:
    /// 1. Fetches the notarizer endorsement from instance user-data in metadata
    /// 2. Generates a vTPM quote using the endorsed AK
    /// 3. Returns the combined attestation document
    async fn generate_attestation_document(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
    ) -> anyhow::Result<Self::AttestationDocument> {
        let mut ak_handle = AttestationKeyHandle::create_from_template_at_nvindex(
            &mut self.tpm_ctx,
            AKTEMPLATE_NVINDEX_ECC.try_into()?,
        )?;

        let quote = ak_handle.quote(pcr_selection_list)?;

        // Generate the quote
        let quote = ak_handle
            .quote(pcr_selection_list)
            .context("Failed to generate vTPM quote")?;

        log::info!("Successfully generated Shielded VM attestation document");

        Ok(ShieldedVmAttestationDocument {
            quote,
            notarizer_endorsement: self.notarizer_endorsement.clone(),
        })
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::{BufWriter, Write};

    use crate::ShieldedVmAttestationDocumentGenerator;
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
    async fn test_gcp_shielded_vm_attestation_document() -> anyhow::Result<()> {
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
            .build()?;

        let _doc = ShieldedVmAttestationDocumentGenerator::new_with_default()
            .await?
            .generate_attestation_document(&pcr_selection_list)
            .await?;

        let file = File::create("test_data/gcp_shielded_vm_attestation_document.json")?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &_doc)?;
        writer.flush()?;

        Ok(())
    }
}

#![feature(doc_notable_trait)]

//! Attestation for Azure CVM platforms

pub mod common;

#[cfg(feature = "generate")]
pub mod generate;

#[cfg(feature = "verify")]
pub mod verify;

#[cfg(feature = "generate")]
pub use generate::*;

#[cfg(test)]
mod test {
    use std::fs;

    use anyhow::Context;
    use attestation::{AsyncGenerateAttestationDocument, AsyncVerifyAttestationDocument};
    use rustls_pki_types::UnixTime;
    use tss_esapi::{interface_types::algorithm::HashingAlgorithm, structures::PcrSelectionList};

    use crate::{
        common::ConfidentialVmAttestationDocument, generate::AzureCvmAttestationDocumentGenerator,
        vtpm::ALL_SLOTS,
    };
    use env_logger::Env;

    #[cfg(test)]
    pub(crate) fn init_logger_tests() {
        // Will fail if called more than once, but I don't care about that type of error so i can just discard it.
        let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info")).try_init();
    }

    #[tokio::test]
    #[ignore]
    async fn test_azure_cvm_generate_attestation() -> anyhow::Result<()> {
        init_logger_tests();

        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
            .build()?;

        let doc = AzureCvmAttestationDocumentGenerator::new()
            .generate_attestation_document(&pcr_selection_list)
            .await?;

        fs::write(
            "attestation_document_new.json",
            serde_json::to_string(&doc)?,
        )?;
        log::info!("{:?}", doc);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_azure_cvm_generate_and_verify() -> anyhow::Result<()> {
        init_logger_tests();
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
            .build()?;

        let evidence = AzureCvmAttestationDocumentGenerator::new()
            .generate_attestation_document(&pcr_selection_list)
            .await?;

        evidence.verify(UnixTime::now()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_gpu_evidence_verify() -> anyhow::Result<()> {
        init_logger_tests();
        let doc: ConfidentialVmAttestationDocument = serde_json::from_slice(
            &fs::read("./test_data/attestation_document.json").context("Error reading file")?,
        )
        .context("Error parsing file to ConfidentialVmAttestationDocument")?;

        doc.verify(UnixTime::now()).await?;

        Ok(())
    }
}

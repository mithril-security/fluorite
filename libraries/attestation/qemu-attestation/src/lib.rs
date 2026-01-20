#![feature(doc_notable_trait)]

//! Attestation for QEMU VMs

mod common;
pub use common::*;

#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "generate")]
pub(crate) mod generate;

#[cfg(feature = "generate")]
pub use generate::*;

#[cfg(test)]
mod test {
    use attestation::{AsyncGenerateAttestationDocument as _, VerifyAttestationDocument as _};
    use rustls_pki_types::UnixTime;
    use tss_esapi::{
        interface_types::algorithm::HashingAlgorithm,
        structures::{PcrSelectionList, PcrSlot},
    };

    use crate::QEMUVmAttestationDocumentGenerator;

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
    async fn test_generate_and_verify() -> anyhow::Result<()> {
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
            .build()?;

        let doc = QEMUVmAttestationDocumentGenerator::new_with_default()?
            .generate_attestation_document(&pcr_selection_list)
            .await?;

        doc.verify(UnixTime::now())?;

        Ok(())
    }
}

use anyhow::{Context, bail};
use attestation::AsyncGenerateAttestationDocument as _;
use azure_cvm_attestation::AzureCvmAttestationDocumentGenerator;
use azure_trusted_launch_attestation::TrustedLaunchVmAttestationDocumentGenerator;
use gcp_shielded_vm_attestation::ShieldedVmAttestationDocumentGenerator;
use provisioning_structs::structs::{AttestationBackend, NodeAttestationDocument};
use qemu_attestation::QEMUVmAttestationDocumentGenerator;
use svsm_sev_attestation::SvsmVtpmAttestationDocumentGenerator;
use tpm_quote::generate::{AttestationKeyHandle, tpm_context};
use tss_esapi::handles::TpmHandle;
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

async fn qemu_get_attestation_document() -> anyhow::Result<NodeAttestationDocument> {
    let pcr_selection_list = PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
        .build()?;

    Ok(NodeAttestationDocument::QEMUVmAttestationDocument(
        QEMUVmAttestationDocumentGenerator::new_with_default()?
            .generate_attestation_document(&pcr_selection_list)
            .await?,
    ))
}

async fn azure_get_attestation_document() -> anyhow::Result<NodeAttestationDocument> {
    let pcr_selection_list = PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
        .build()?;

    Ok(NodeAttestationDocument::TrustedLaunchVmAttestationDocument(
        TrustedLaunchVmAttestationDocumentGenerator::new_with_default()?
            .generate_attestation_document(&pcr_selection_list)
            .await?,
    ))
}

async fn baremetal_get_attestation_document() -> anyhow::Result<NodeAttestationDocument> {
    let pcr_selection_list = PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
        .build()?;

    Ok(NodeAttestationDocument::SvsmVtpmAttestationDocument(
        SvsmVtpmAttestationDocumentGenerator::new_with_default()?
            .generate_attestation_document(&pcr_selection_list)
            .await?,
    ))
}

async fn azure_cvm_get_attestation_document() -> anyhow::Result<NodeAttestationDocument> {
    let pcr_selection_list = PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
        .build()?;

    Ok(NodeAttestationDocument::ConfidentialVMAttestationDocument(
        AzureCvmAttestationDocumentGenerator::new()
            .generate_attestation_document(&pcr_selection_list)
            .await?,
    ))
}

/// Generate attestation document for GCP Shielded VM using the provided endorsement
async fn gcp_shielded_vm_get_attestation_document() -> anyhow::Result<NodeAttestationDocument> {
    let pcr_selection_list = PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, ALL_SLOTS)
        .build()?;

    Ok(NodeAttestationDocument::GcpShieldedVmAttestationDocument(
        ShieldedVmAttestationDocumentGenerator::new_with_default()
            .await?
            .generate_attestation_document(&pcr_selection_list)
            .await?,
    ))
}

pub(crate) async fn get_attestation_document(
    attestation_backend: AttestationBackend,
) -> anyhow::Result<NodeAttestationDocument> {
    match attestation_backend {
        AttestationBackend::QEMU => qemu_get_attestation_document().await,
        AttestationBackend::AzureTrustedLaunchVM => azure_get_attestation_document().await,
        AttestationBackend::SvsmVtpm => baremetal_get_attestation_document().await,
        AttestationBackend::AzureConfidentialVM => azure_cvm_get_attestation_document().await,
        AttestationBackend::GcpShieldedVM => gcp_shielded_vm_get_attestation_document().await,
    }
}

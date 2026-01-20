//! CVM attestation handling for the notarizer
//!
//! This module handles obtaining attestation documents from the GCP CVM
//! that proves the notarizer is running on genuine confidential computing hardware.

use anyhow::Context;
use attestation::AsyncGenerateAttestationDocument;
use attestation::eventlog::{Event, EventLog, LiveEventLog};
use attestation::msg::{MessageKeyPair, MessageVerifyingKey, Msg, MsgEnum, SignedMessage};
use derive_more::{From, TryInto};
use gcp_cvm_attestation::{
    CvmAttestationDocument, CvmAttestationDocumentGenerator, PcrSelectionList, PcrSlot,
    TssHashingAlgorithm,
};
use log::info;
use serde::{Deserialize, Serialize};
use tpm_quote::common::{HashingAlgorithm, PcrIndex, PcrSlot as TpmPcrSlot};
use tpm_quote::generate::tpm_context;

use crate::gcp_api::ShieldedVmIdentity;

/// PCR slot used for the notarizer's event log
/// Using PCR 8 which is typically available for application use
pub const NOTARIZER_EVENT_LOG_SLOT: PcrIndex = PcrIndex {
    bank: HashingAlgorithm::Sha256,
    pcr_slot: TpmPcrSlot::Slot8,
};

/// All PCR slots for attestation
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

/// Events that the notarizer logs to the TPM
#[derive(Serialize, Deserialize, Clone, Debug, From, TryInto)]
pub enum NotarizerEvent {
    /// Logged at startup with the signing public key
    NotarizerStarted(NotarizerStartedEvent),
}

impl Event for NotarizerEvent {}

/// Event logged when the notarizer starts
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NotarizerStartedEvent {
    /// The public key used for signing notarizations
    pub signing_public_key: MessageVerifyingKey<NotarizerMessage>,
}

/// Event logged when a Shielded VM identity is notarized (optional audit trail)
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShieldedVmNotarizedEvent {
    /// GCP project
    pub project: String,
    /// GCP zone
    pub zone: String,
    /// Instance name
    pub instance: String,
    /// Timestamp of notarization (ISO 8601)
    pub timestamp: String,
}

// ============================================================================
// Message Types for Signed Messages
// ============================================================================

/// Enum of message types that can be signed by the notarizer
#[derive(Serialize, Deserialize, Clone, Debug, From, TryInto)]
pub enum NotarizerMessage {
    /// A notarized Shielded VM identity
    NotarizedShieldedVmIdentity(NotarizedShieldedVmIdentityPayload),
}

impl MsgEnum for NotarizerMessage {}

/// The payload that gets signed when notarizing a Shielded VM identity
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NotarizedShieldedVmIdentityPayload {
    /// The raw Shielded VM identity from GCP API
    pub shielded_vm_identity: ShieldedVmIdentity,
    /// Timestamp when this notarization was created (ISO 8601)
    pub notarized_at: String,
    /// GCP project
    pub project: String,
    /// GCP zone
    pub zone: String,
    /// Instance name
    pub instance: String,
}

impl Msg for NotarizedShieldedVmIdentityPayload {
    type MsgEnum = NotarizerMessage;
}

// ============================================================================
// Notarizer Attestation Document
// ============================================================================

/// The notarizer's attestation document
///
/// This contains:
/// - The CVM attestation (vTPM quote + AK certificate chain)
/// - The event log showing the signing public key was registered at startup
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NotarizerAttestation {
    /// The CVM attestation document from GCP
    pub cvm_attestation: CvmAttestationDocument,

    /// The event log (serialized events that can be replayed to verify PCR 8)
    pub event_log: EventLog<NotarizerEvent>,
}

/// State of the notarizer that can generate new attestations
pub struct NotarizerState {
    /// The live event log (can extend PCR)
    event_log: LiveEventLog<NotarizerEvent>,

    /// The signing key pair
    signing_keypair: MessageKeyPair<NotarizerMessage>,
}

impl NotarizerState {
    /// Create a new notarizer state by initializing the TPM and generating a signing key
    pub fn new() -> anyhow::Result<Self> {
        info!("Initializing notarizer state...");

        // Create TPM context
        let tpm_ctx = tpm_context().context("Failed to create TPM context")?;

        // Create the live event log backed by PCR 8
        let event_log = LiveEventLog::new(tpm_ctx, NOTARIZER_EVENT_LOG_SLOT);

        // Generate the signing key pair
        let signing_keypair = NotarizerMessage::new_keypair();

        Ok(Self {
            event_log,
            signing_keypair,
        })
    }

    /// Get the verifying key for signing operations
    pub fn verifying_key(&self) -> MessageVerifyingKey<NotarizerMessage> {
        self.signing_keypair.verifying_key()
    }

    /// Log the startup event and generate the initial attestation
    pub async fn initialize_and_attest(&mut self) -> anyhow::Result<NotarizerAttestation> {
        info!("Logging startup event to TPM...");

        // Log the startup event with the verifying key
        self.event_log
            .push_event(&NotarizerEvent::NotarizerStarted(NotarizerStartedEvent {
                signing_public_key: self.signing_keypair.verifying_key(),
            }))
            .context("Failed to push startup event to TPM")?;

        info!("Startup event logged. Generating CVM attestation...");

        // Generate the CVM attestation
        self.generate_attestation().await
    }

    /// Generate a fresh CVM attestation with current event log state
    pub async fn generate_attestation(&self) -> anyhow::Result<NotarizerAttestation> {
        // Build PCR selection for all slots
        let pcr_selection_list = PcrSelectionList::builder()
            .with_selection(TssHashingAlgorithm::Sha256, ALL_SLOTS)
            .build()
            .context("Failed to build PCR selection list")?;

        // Create a new TPM context for attestation generation
        let tpm_ctx = tpm_context().context("Failed to create TPM context for attestation")?;
        let mut generator = CvmAttestationDocumentGenerator::new_with_tpm_ctx(tpm_ctx);

        // Generate the attestation document
        let cvm_attestation = generator
            .generate_attestation_document(&pcr_selection_list)
            .await
            .context("Failed to generate CVM attestation document")?;

        info!("CVM attestation document generated successfully");
        info!(
            "AK certificate chain has {} certificates",
            cvm_attestation.ak_cert_chain.len()
        );

        Ok(NotarizerAttestation {
            cvm_attestation,
            event_log: self.event_log.get_eventlog().clone(),
        })
    }

    /// Sign a notarized Shielded VM identity payload
    pub fn sign_payload(
        &self,
        payload: &NotarizedShieldedVmIdentityPayload,
    ) -> anyhow::Result<SignedMessage<NotarizedShieldedVmIdentityPayload>> {
        self.signing_keypair
            .sign(payload)
            .context("Failed to sign payload")
    }

    /// Get the current event log
    #[allow(dead_code)]
    pub fn get_event_log(&self) -> &EventLog<NotarizerEvent> {
        self.event_log.get_eventlog()
    }
}

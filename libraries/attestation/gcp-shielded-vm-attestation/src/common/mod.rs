//! Common types for GCP Shielded VM attestation

use attestation::eventlog::{Event, EventLog};
use attestation::msg::{MessageVerifyingKey, Msg, MsgEnum, SignedMessage};
use derive_more::{From, TryInto};
use gcp_cvm_attestation::CvmAttestationDocument;
use serde::{Deserialize, Serialize};
use tpm_quote::common::Quote;

/// NV Index of the GCP ECC AK template
pub const AKTEMPLATE_NVINDEX_ECC: u32 = 0x01c10003;
// ============================================================================
// Shielded VM Identity Types (from GCP API)
// ============================================================================

/// Shielded Instance Identity response from GCP API
///
/// Reference: https://cloud.google.com/compute/docs/reference/rest/v1/instances/getShieldedInstanceIdentity
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShieldedInstanceIdentity {
    /// The kind of resource (always "compute#shieldedInstanceIdentity")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// An Attestation Key (AK) made by the RSA 2048 algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<ShieldedInstanceIdentityEntry>,

    /// An Endorsement Key (EK) made by the RSA 2048 algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<ShieldedInstanceIdentityEntry>,

    /// An Attestation Key (AK) made by the ECC P256 algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p256_signing_key: Option<ShieldedInstanceIdentityEntry>,

    /// An Endorsement Key (EK) made by the ECC P256 algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p256_encryption_key: Option<ShieldedInstanceIdentityEntry>,
}

/// An identity entry containing the key and optional certificate
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ShieldedInstanceIdentityEntry {
    /// A PEM-encoded public key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_pub: Option<String>,

    /// A PEM-encoded X.509 certificate (this field can be empty for Shielded VMs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ek_cert: Option<String>,
}

// ============================================================================
// Notarizer Types (must match gcp-shielded-vm-notarizer)
// ============================================================================

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

/// Event logged when a Shielded VM identity is notarized
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
    pub shielded_vm_identity: ShieldedInstanceIdentity,
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

/// The notarizer's attestation document
///
/// This contains:
/// - The CVM attestation (vTPM quote + AK certificate chain)
/// - The event log showing the signing public key was registered at startup
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NotarizerAttestation {
    /// The CVM attestation document from GCP CVM
    pub cvm_attestation: CvmAttestationDocument,

    /// The event log (serialized events that can be replayed to verify PCR 8)
    pub event_log: EventLog<NotarizerEvent>,
}

/// Response from the notarizer containing the notarized identity and attestation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NotarizeResponse {
    /// The notarized Shielded VM identity
    pub notarized_identity: SignedMessage<NotarizedShieldedVmIdentityPayload>,

    /// The notarizer's CVM attestation (proves the signing key is genuine)
    pub notarizer_attestation: NotarizerAttestation,
}

// ============================================================================
// Shielded VM Attestation Document
// ============================================================================

/// Attestation document for GCP Shielded VM.
///
/// Unlike CVMs, Shielded VMs don't have an AK certificate chain.
/// Instead, they rely on a notarizer (running on a CVM) to endorse
/// their attestation key.
///
/// The verification chain is:
/// 1. Verify the notarizer's CVM attestation (proving it runs on genuine CVM)
/// 2. Verify the notarizer's event log to extract the signing key
/// 3. Verify the notarizer signed the Shielded VM's identity
/// 4. Extract the AK public key from the signed identity
/// 5. Verify the vTPM quote was signed by that AK
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShieldedVmAttestationDocument {
    /// The vTPM quote from the Shielded VM
    pub quote: Quote,

    /// The notarizer's response endorsing this VM's attestation key
    pub notarizer_endorsement: NotarizeResponse,
}

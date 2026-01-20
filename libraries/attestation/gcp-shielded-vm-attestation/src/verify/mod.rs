//! Verification of GCP Shielded VM attestation documents

use crate::{
    NotarizerAttestation, NotarizerEvent, NotarizerStartedEvent, ShieldedVmAttestationDocument,
};
use anyhow::Context;
use attestation::eventlog::{EventLog, ParsedEventLog};
use attestation::msg::MessageVerifyingKey;
use attestation::VerifyAttestationDocument;
use fn_error_context::context;
use rustls_pki_types::UnixTime;
use sha2::Sha256;
use tpm_quote::common::{HashingAlgorithm, PcrSlot, SanitizedPcrData};
use tpm_quote::verify::{AttestationKey, EccAttestationKey};

use super::NotarizerMessage;

/// PCR slot used for the notarizer's event log (must match notarizer's NOTARIZER_EVENT_LOG_SLOT)
const NOTARIZER_EVENT_LOG_PCR_SLOT: PcrSlot = PcrSlot::Slot8;

impl VerifyAttestationDocument for ShieldedVmAttestationDocument {
    /// Verify the Shielded VM attestation document.
    ///
    /// This performs the full verification chain:
    /// 1. Verify the notarizer's CVM attestation
    /// 2. Verify the event log matches PCR 8 and extract the signing key
    /// 3. Verify the notarizer signed the Shielded VM's identity
    /// 4. Extract the AK public key from the signed identity
    /// 5. Verify the vTPM quote was signed by that AK
    #[context("ShieldedVmAttestationDocument::verify failed")]
    fn verify(&self, now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        let ShieldedVmAttestationDocument {
            quote,
            notarizer_endorsement,
        } = self;

        // Step 1: Verify the notarizer's CVM attestation
        let notarizer_pcr_data =
            verify_notarizer_attestation(&notarizer_endorsement.notarizer_attestation, now)?;

        // Step 2: Verify event log and extract signing key
        let signing_key = verify_notarizer_event_log(
            &notarizer_endorsement.notarizer_attestation.event_log,
            &notarizer_pcr_data,
        )?;

        // Step 3: Verify the notarizer signed the Shielded VM identity
        let payload = signing_key
            .verify(&notarizer_endorsement.notarized_identity)
            .context("Failed to verify notarizer signature on Shielded VM identity")?;

        // Step 4: Extract the AK public key from the signed identity
        // Use the RSA signing key (most common for vTPM quotes)
        let ak_pem = payload
            .shielded_vm_identity
            .ecc_p256_signing_key
            .as_ref()
            .and_then(|k| k.ek_pub.as_ref())
            .context("Shielded VM identity missing RSA signing key (AK)")?;

        let ak = EccAttestationKey::try_from_pem(ak_pem)
            .context("Failed to parse ECC attestation key from PEM")?;

        // Step 5: Verify the vTPM quote was signed by the endorsed AK
        let pcr_data = ak
            .verify_quote(quote)
            .context("Failed to verify vTPM quote with endorsed AK")?;

        log::info!(
            "Successfully verified Shielded VM attestation for {}/{}/{}",
            payload.project,
            payload.zone,
            payload.instance
        );

        Ok(pcr_data)
    }
}

/// Verify the notarizer's CVM attestation
#[context("Failed to verify notarizer CVM attestation")]
fn verify_notarizer_attestation(
    notarizer_attestation: &NotarizerAttestation,
    now: UnixTime,
) -> anyhow::Result<SanitizedPcrData> {
    // Verify the CVM attestation document (vTPM quote + AK cert chain)
    let pcr_data = notarizer_attestation
        .cvm_attestation
        .verify(now)
        .context("CVM attestation verification failed")?;

    log::debug!("Notarizer CVM attestation verified successfully");
    Ok(pcr_data)
}

/// Verify the notarizer's event log matches PCR 8 and extract the signing key
#[context("Failed to verify notarizer event log")]
fn verify_notarizer_event_log(
    event_log: &EventLog<NotarizerEvent>,
    pcr_data: &SanitizedPcrData,
) -> anyhow::Result<MessageVerifyingKey<NotarizerMessage>> {
    // Get the expected PCR 8 value from the attestation
    let sha256_bank = pcr_data
        .pcr_bank(HashingAlgorithm::Sha256)
        .context("SHA256 PCR bank not found in notarizer attestation")?;

    let expected_pcr8 = sha256_bank
        .bank
        .get(&NOTARIZER_EVENT_LOG_PCR_SLOT)
        .context("PCR 8 not found in notarizer attestation")?;

    // Convert to the expected digest type
    let expected_digest: [u8; 32] = expected_pcr8
        .0
        .as_slice()
        .try_into()
        .context("PCR 8 value is not 32 bytes")?;

    // Verify the event log against the expected PCR value and parse events
    let parsed_event_log: ParsedEventLog<NotarizerEvent> = event_log
        .verify::<Sha256>(expected_digest.into())
        .context("Event log verification failed - PCR mismatch")?;

    // let parsed_event_log = event_log.unsafe_open()?;

    log::debug!("Event log verified, PCR 8 matches");

    // Extract the signing key from the NotarizerStarted event
    let signing_key = parsed_event_log
        .iter()
        .find_map(|event| {
            match event {
                NotarizerEvent::NotarizerStarted(NotarizerStartedEvent { signing_public_key }) => Some(signing_public_key.clone()),
            }
        })
        .context("NotarizerStarted event not found in event log")?;

    log::debug!("Extracted notarizer signing key from event log");
    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_gcp_shielded_vm_attestation_document_verify_ok() -> anyhow::Result<()> {
        let doc: ShieldedVmAttestationDocument = serde_json::from_slice(&fs::read(
            "test_data/gcp_shielded_vm_attestation_document.json",
        )?)?;

        let pcr_data = doc.verify(UnixTime::now())?;
        insta::assert_debug_snapshot!(pcr_data);
        Ok(())
    }
    #[test]
    fn test_gcp_cvm_eventlog_notarizer_attestation_with_eventlog() -> anyhow::Result<()> {
        // This test verifies that we can parse a notarizer attestation + eventlog from test data

        let bytes = fs::read("test_data/gcp_cvm_eventlog.json")?;
        let attest: NotarizerAttestation = serde_json::from_slice(&bytes)?;

        // Use the helper to verify the event log and extract the signing key
        let event_log = verify_notarizer_event_log(
            &attest.event_log,
            &attest.cvm_attestation.verify(UnixTime::now())?,
        )?;

        println!("Event log: {:?}", event_log);
        Ok(())
    }
}

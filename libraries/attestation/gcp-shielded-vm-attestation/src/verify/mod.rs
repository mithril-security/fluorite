//! Verification of GCP Shielded VM attestation documents

use crate::{
    NotarizeResponse, NotarizerEvent, NotarizerStartedEvent, ShieldedVmAttestationDocument,
};
use anyhow::{bail, Context};
use attestation::eventlog::ParsedEventLog;
use attestation::VerifyAttestationDocument;
use fn_error_context::context;
use rustls_pki_types::UnixTime;
use sha2::Sha256;
use tpm_quote::common::{Digest, HashingAlgorithm, PcrData, PcrSlot, SanitizedPcrData};
use tpm_quote::verify::{AttestationKey, EccAttestationKey};

/// PCR slot used for the notarizer's event log (must match notarizer's NOTARIZER_EVENT_LOG_SLOT)
const NOTARIZER_EVENT_LOG_PCR_SLOT: PcrSlot = PcrSlot::Slot8;

/// PCR slot for OS image measurement
const OS_IMAGE_PCR_SLOT: PcrSlot = PcrSlot::Slot4;

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Serialize, Deserialize)]
struct GcpNotarizerMeasurements {
    golden_pcr_data: PcrData,
    expected_os_image_measurement: Digest,
}

static GCP_NOTARIZER_MEASUREMENTS: LazyLock<GcpNotarizerMeasurements> = LazyLock::new(|| {
    const JSON: &str = include_str!("../../gcp_notarizer_measurements.json");
    serde_json::from_str(JSON)
        .expect("Failed to parse gcp_notarizer_measurements.json at compile time")
});

impl VerifyAttestationDocument for ShieldedVmAttestationDocument {
    /// Verify the Shielded VM attestation document.
    ///
    /// This performs the full verification chain:
    /// 1. Validate notarizer endorsement and obtain the AK
    /// 2. Verify the vTPM quote was signed by that AK
    #[context("ShieldedVmAttestationDocument::verify failed")]
    fn verify(&self, now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        let ShieldedVmAttestationDocument {
            quote,
            notarizer_endorsement,
        } = self;

        let ak = verify_notarizer_response(
            &notarizer_endorsement,
            &GCP_NOTARIZER_MEASUREMENTS.golden_pcr_data,
            &GCP_NOTARIZER_MEASUREMENTS.expected_os_image_measurement,
            now,
        )?;

        let pcr_data = ak
            .verify_quote(&quote)
            .context("Failed to verify vTPM quote with endorsed AK")?;

        Ok(pcr_data)
    }
}

/// Verify a notarizer response and extract the Shielded VM's attestation key.
///
/// This function performs the complete verification of a notarizer response:
/// 1. Verifies the notarizer's CVM attestation
/// 2. Validates that the notarizer's PCR data is a superset of the golden PCR values
/// 3. Checks that PCR4 (OS image) matches the expected measurement
/// 4. Verifies the event log and extracts the signing key
/// 5. Verifies the notarizer's signature on the Shielded VM identity
/// 6. Extracts and returns the AK from the signed identity
///
/// # Arguments
/// * `notarize_response` - The response from the notarizer containing the signed identity and attestation
/// * `golden_pcr_data` - The expected golden PCR values (notarizer PCRs must be superset of this)
/// * `expected_pcr4` - The expected PCR4 value (SHA256 digest) for the OS image measurement
/// * `now` - Current time for certificate validation
///
/// # Returns
/// The ECC attestation key (AK) of the Shielded VM on success
#[context("Failed to verify notarizer response")]
pub fn verify_notarizer_response(
    notarize_response: &NotarizeResponse,
    golden_pcr_data: &PcrData,
    expected_pcr4: &Digest,
    now: UnixTime,
) -> anyhow::Result<EccAttestationKey> {
    // Step 1: Verify the notarizer's CVM attestation
    let notarizer_pcr_data = notarize_response
        .notarizer_attestation
        .cvm_attestation
        .verify(now)
        .context("CVM attestation verification failed")?;

    // Step 2: Validate that notarizer PCR data is a superset of golden PCR values
    if !golden_pcr_data.is_subset(&notarizer_pcr_data) {
        bail!(
            "Notarizer PCR data does not match golden PCR values, expected: {:?}, got: {:?}",
            golden_pcr_data,
            notarizer_pcr_data
        );
    }
    log::debug!("Notarizer PCR data validated against golden values");

    // Step 3: Check PCR4 (OS image) matches expected measurement
    let sha256_bank = notarizer_pcr_data
        .pcr_bank(HashingAlgorithm::Sha256)
        .context("SHA256 PCR bank not found in notarizer attestation")?;

    let actual_pcr4 = sha256_bank
        .bank
        .get(&OS_IMAGE_PCR_SLOT)
        .context("PCR4 not found in notarizer attestation")?;

    if actual_pcr4 != expected_pcr4 {
        bail!(
            "PCR4 mismatch: expected {:?}, got {:?}",
            expected_pcr4,
            actual_pcr4
        );
    }
    log::debug!("PCR4 (OS image) measurement verified");

    // Step 4: Verify event log and extract signing key
    let expected_pcr8 = sha256_bank
        .bank
        .get(&NOTARIZER_EVENT_LOG_PCR_SLOT)
        .context("PCR8 not found in notarizer attestation")?;

    let expected_pcr8_digest: [u8; 32] = expected_pcr8
        .0
        .as_slice()
        .try_into()
        .context("PCR8 value is not 32 bytes")?;

    let parsed_event_log: ParsedEventLog<NotarizerEvent> = notarize_response
        .notarizer_attestation
        .event_log
        .verify::<Sha256>(expected_pcr8_digest.into())
        .context("Event log verification failed - PCR mismatch")?;

    log::debug!("Event log verified, PCR8 matches");

    let signing_key = parsed_event_log
        .iter()
        .find_map(|event| match event {
            NotarizerEvent::NotarizerStarted(NotarizerStartedEvent { signing_public_key }) => {
                Some(signing_public_key.clone())
            }
        })
        .context("NotarizerStarted event not found in event log")?;

    log::debug!("Extracted notarizer signing key from event log");

    // Step 5: Verify the notarizer signed the Shielded VM identity
    let payload = signing_key
        .verify(&notarize_response.notarized_identity)
        .context("Failed to verify notarizer signature on Shielded VM identity")?;

    // Step 6: Extract the AK public key from the signed identity
    let ak_pem = payload
        .shielded_vm_identity
        .ecc_p256_signing_key
        .as_ref()
        .and_then(|k| k.ek_pub.as_ref())
        .context("Shielded VM identity missing ECC P256 signing key (AK)")?;

    let ak = EccAttestationKey::try_from_pem(ak_pem)
        .context("Failed to parse ECC attestation key from PEM")?;

    log::info!(
        "Successfully verified notarizer response for {}/{}/{}",
        payload.project,
        payload.zone,
        payload.instance
    );

    Ok(ak)
}

#[cfg(test)]
mod tests {
    use tpm_quote::common::PcrBank;

    use super::*;
    use std::fs;

    #[test]
    #[ignore = "Requires golden PCR data and OS image measurement for notarizer"]
    fn test_gcp_shielded_vm_attestation_document_verify_ok() -> anyhow::Result<()> {
        let doc: ShieldedVmAttestationDocument = serde_json::from_slice(&fs::read(
            "test_data/gcp_shielded_vm_attestation_document.json",
        )?)?;

        // TODO: Load golden PCR data and expected OS image measurement from test data
        let pcr_data = doc.verify(UnixTime::now())?;
        insta::assert_debug_snapshot!(pcr_data);
        Ok(())
    }
    /// Returns a demo/test instance of GcpNotarizerMeasurements for testing purposes.
    /// Note: The digest and PCR data here are not cryptographically valid.
    #[test]
    pub fn demo_gcp_notarizer_measurements() -> anyhow::Result<()> {
        use std::collections::BTreeMap;
        use tpm_quote::common::{Digest, HashingAlgorithm, PcrData, PcrSlot};

        // Example SHA256 digest (32 bytes). This is dummy data.
        let dummy_digest = Digest(vec![
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
        ]);

        // Example PcrData - only partial slots filled, the rest omitted for brevity.
        let mut bank = BTreeMap::new();
        bank.insert(PcrSlot::Slot0, dummy_digest.clone());
        bank.insert(PcrSlot::Slot4, dummy_digest.clone());
        bank.insert(PcrSlot::Slot8, dummy_digest.clone());

        let pcr_data = PcrData {
            data: vec![(HashingAlgorithm::Sha256, PcrBank { bank })],
        };

        let gcp_notarizer_measurements = GcpNotarizerMeasurements {
            golden_pcr_data: pcr_data,
            expected_os_image_measurement: dummy_digest,
        };
        let json = serde_json::to_string_pretty(&gcp_notarizer_measurements)?;
        fs::write("gcp_notarizer_measurements_demo.json", json)?;

        Ok(())
    }
}

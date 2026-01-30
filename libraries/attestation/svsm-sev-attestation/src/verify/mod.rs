mod collateral;

use crate::SvsmVtpmAttestationDocument;
use anyhow::{bail, ensure, Context, Ok};
use attestation::VerifyAttestationDocument;
use collateral::validate_cert_metadata;
use rustls_pki_types::UnixTime;
use sev::{
    certs::snp::{self, ca, Certificate, Verifiable},
    CpuFamily, CpuModel, Generation,
};
use sha2::{Digest, Sha512};
use tpm_quote::common::{Digest as TpmDigest};

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tpm_quote::{
    common::SanitizedPcrData,
    verify::{AttestationKey, EccAttestationKey},
};

#[derive(Serialize, Deserialize)]
struct BaremetalMeasurements {
    igvm_measurement: TpmDigest,
}

static BAREMETAL_MEASUREMENTS: LazyLock<BaremetalMeasurements> = LazyLock::new(|| {
    const JSON: &str = include_str!("../../baremetal_measurements.json");
    serde_json::from_str(JSON)
        .expect("Failed to parse igvm_measurement.json at compile time")
});

impl VerifyAttestationDocument for SvsmVtpmAttestationDocument {
    fn verify(&self, _now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        // TODO: Use arg now to check for expiration
        // Reference: https://www.amd.com/content/dam/amd/en/documents/developer/58217-epyc-9004-ug-platform-attestation-using-virtee-snp.pdf

        if *self.attestation_report.measurement != *BAREMETAL_MEASUREMENTS.igvm_measurement.0 {
            bail!("Attestation Report measurement doesn't match the expected IGVM measurement. \nExpected: {}\nGot: {}", hex::encode(BAREMETAL_MEASUREMENTS.igvm_measurement.0.clone()), hex::encode(*self.attestation_report.measurement));
        }
        let nonce = [0u8; 64];
        let nonce_and_manifest = [&nonce[..], &self.ak_pub_key[..]].concat();
        let hash = Sha512::digest(&nonce_and_manifest);

        // Verifying AK pub key against Attestation report
        // let hash_ak_pkey = sha512(&ak_pub_key);
        if *self.attestation_report.report_data != *hash {
            bail!("Report data doesn't match the hash of the AK public key. \nreport_data {} \nhash_ak_pkey {}", hex::encode(self.attestation_report.report_data), hex::encode(hash))
        }

        ensure!(
            !self.attestation_report.policy.debug_allowed(),
            "Policy allows debug mode but should not"
        );
        ensure!(
            !self.attestation_report.policy.migrate_ma_allowed(),
            "Policy allows migration but should not"
        );
        // NOTE: We use policy 0x3000
        // - PAGE SWAPPING is not disabled.
        // - Ciphertext hiding for the DRAM is not enabled.
        // - Allow Running Average Power Limit (RAPL).
        // - Allow AES 128 XEX or AES 256 XTS for memory encryption.
        // - CXL cannot be populated with devices or memory.
        // - Guest can be activated on multiple sockets.
        // - Debugging is disallowed.
        // - Migration agent is disallowed.
        // - SMT is allowed.
        // - ABI Minor/Major is not set for this VM.

        // ensure!(self.attestation_report.policy.ciphertext_hiding(), "Policy should enforce ciphertext hiding but does not");
        // ensure!(self.attestation_report.policy.mem_aes_256_xts(), "Policy should enforce AES-256-XTS but does not");
        // ensure!(self.attestation_report.policy.single_socket_required(), "Policy should enforce single socket but does not");

        let chip_id = self.attestation_report.chip_id;

        let reported_tcb = self.attestation_report.reported_tcb;

        let cpu_familiy: CpuFamily =
            self.attestation_report
                .cpuid_fam_id
                .ok_or(anyhow::format_err!(
                    "Error getting the cpuid_fam_id from the AttestationReport"
                ))?;
        let cpu_model: CpuModel =
            self.attestation_report
                .cpuid_mod_id
                .ok_or(anyhow::format_err!(
                    "Error getting the cpuid_mod_id from the AttestationReport"
                ))?;
        let host_generation = Generation::try_from((cpu_familiy, cpu_model)).context(format!("Error converting cpu_family={}, cpu_model={} to a known SEV-SNP enabled CPU generation", cpu_familiy, cpu_model))?;

        let ca_chain = ca::Chain::from(host_generation);
        let _ = ca_chain.verify()?;

        let vek = Certificate::from_der(&self.sev_cert_chain.vek_der)?;

        // Verifying VCEK metadata
        validate_cert_metadata(&vek, *chip_id, reported_tcb)
            .context("VCEK metadata verification Failed. Certificate does not match the report.")?;

        let chain: snp::Chain = snp::Chain {
            ca: ca_chain,
            vek: vek,
        };

        // Verify chain and attestation report signature
        (&chain, &self.attestation_report).verify()?;

        // Get the PCRs
        let ak = EccAttestationKey::try_from_tpmt_public(&self.ak_pub_key)?;
        let pcr_data = ak.verify_quote(&self.quote).context("Verifying quote")?;

        Ok(pcr_data)
    }
}

#[cfg(test)]
mod test {
    use crate::SvsmVtpmAttestationDocument;
    use attestation::VerifyAttestationDocument;
    use rustls_pki_types::UnixTime;

    #[test]
    fn test_svsm_attestation_document_verify() -> anyhow::Result<()> {
        use std::fs;
        use std::result::Result::Ok;

        let attestation_doc: SvsmVtpmAttestationDocument = serde_json::from_slice(&fs::read(
            "test_data/amd_sev_snp_vm_attestation_document.json",
        )?)?;
        let pcr_data = attestation_doc.verify(UnixTime::now())?;
        println!("{:?}", pcr_data);
        insta::assert_debug_snapshot!(pcr_data,@r###"
    SanitizedPcrData(
        PcrData {
            data: [
                (
                    Sha256,
                    PcrBank {
                        bank: {
                            Slot0: f2778fd3187f5f6db76b78355cc7a6fb5a84396922bdc211add53ced5667091b,
                            Slot1: d9f841a3a85156d97040aadc152eb25d7dfabf3ec77dca2a4a0dc5f5cecdba7d,
                            Slot2: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot3: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot4: 9dd1b60f266133e0f35d19db0e17244529edca3a67001ab1ffb11a246bdd20c2,
                            Slot5: 593e79e5498be2734a15f8131b2ef77aa3dbc15f2ba026d5ed5cd4c5cd6836e5,
                            Slot6: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot7: b5710bf57d25623e4019027da116821fa99f5c81e9e38b87671cc574f9281439,
                            Slot8: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot9: f763d7440d0621cc9eabc01fc724ba1ee29e694674317d30a9e12cb440eb6cb1,
                            Slot10: 9629923991d2d09fbd2e3d69cedf14b5aa0e619550ad71d4f406e372e9306804,
                            Slot11: 11cc503b832649d63223d28e8778a5fcde62a6484e4ef2c1e18717833acbb630,
                            Slot12: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot13: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot14: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot15: a7365015c30eae41a8a7b80fa54fe84f8d99c46a2e6336b51247c977608c8d20,
                            Slot16: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot17: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                            Slot18: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                            Slot19: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                            Slot20: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                            Slot21: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                            Slot22: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
                            Slot23: 0000000000000000000000000000000000000000000000000000000000000000,
                        },
                    },
                ),
            ],
        },
    )
    "###);
        Ok(())
    }
}

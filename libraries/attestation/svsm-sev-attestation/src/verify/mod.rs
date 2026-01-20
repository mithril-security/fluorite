mod collateral;

use crate::SvsmVtpmAttestationDocument;
use anyhow::{bail, ensure, Context, Ok};
use attestation::VerifyAttestationDocument;
use collateral::validate_cert_metadata;
use rustls_pki_types::UnixTime;
use sev::{
    certs::snp::{self, ca, Certificate, Verifiable},
    firmware::guest::GuestPolicy,
    CpuFamily, CpuModel, Generation,
};
use sha2::{Digest, Sha512};
use tpm_quote::common::Digest as TpmDigest;

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
    serde_json::from_str(JSON).expect("Failed to parse baremetal_measurements.json at compile time")
});

impl VerifyAttestationDocument for SvsmVtpmAttestationDocument {
    fn verify(&self, _now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        // TODO: Use arg now to check for expiration
        // Reference: https://www.amd.com/content/dam/amd/en/documents/developer/58217-epyc-9004-ug-platform-attestation-using-virtee-snp.pdf

        if *self.attestation_report.measurement != *BAREMETAL_MEASUREMENTS.igvm_measurement.0 {
            bail!("Attestation Report measurement doesn't match the expected IGVM measurement. \nExpected: {}\nGot: {}", hex::encode(BAREMETAL_MEASUREMENTS.igvm_measurement.0.clone()), hex::encode(*self.attestation_report.measurement));
        }

        let nonce_and_manifest = [&self.nonce[..], &self.ak_pub_key[..]].concat();
        let hash = Sha512::digest(&nonce_and_manifest);

        // Verifying AK pub key against Attestation report
        // let hash_ak_pkey = sha512(&ak_pub_key);
        if *self.attestation_report.report_data != *hash {
            bail!("Report data doesn't match the hash of the AK public key. \nreport_data {} \nhash_ak_pkey {}", hex::encode(self.attestation_report.report_data), hex::encode(hash))
        }

        // NOTE: We use policy 0x30000
        // QEMU: -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,policy=0x30000
        // - ABI MINOR: 1
        // - ABI MAJOR: 0
        // - SMT is allowed.
        // - Migration agent is disallowed.
        // - Debugging is disallowed.
        // - Guest can be activated on multiple sockets.
        // - CXL cannot be populated with devices or memory.
        // - Allow AES 128 XEX or AES 256 XTS for memory encryption.
        // - Allow Running Average Power Limit (RAPL).
        // - Ciphertext hiding for the DRAM is not enabled.
        // - Page Swapping is not disabled.

        let expected_guest_policy = GuestPolicy(0x30000);
        ensure!(
            self.attestation_report.policy == expected_guest_policy,
            "Expected GuestPolicy(0x{:x}): {:?},\nGot GuestPolicy(0x{:x}): {:?}",
            expected_guest_policy.0,
            expected_guest_policy,
            self.attestation_report.policy.0,
            self.attestation_report.policy
        );

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
                            Slot4: 2e723f3f7caef59272cd0ac4650d6ebd57baca1e00646986870258e7960c2ecc,
                            Slot5: e0fb330152086b4f1ce477f63d52e639d5b6619df781dc951d01a32ba4b57229,
                            Slot6: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot7: b5710bf57d25623e4019027da116821fa99f5c81e9e38b87671cc574f9281439,
                            Slot8: 34731fc0e1c432adf8f5210299ff9de9c8c14ec739b27096d44821f7c4dee188,
                            Slot9: 13e929ae1e091b6b6343769f63d6a73cbca40c9de13a4beaaedf664ef65d27e5,
                            Slot10: 59b8c07a25ab2b8191737211b647551c4f617e0db6871425aa2c62ef5938d9bf,
                            Slot11: 1b5fbf1693760fbbf9273a7ab50f302494018a93c501fea5201e66316058961c,
                            Slot12: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot13: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot14: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot15: ea3683732e88d8d261609fced2030251dcb1115435a28fcb2d537857d0809d17,
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

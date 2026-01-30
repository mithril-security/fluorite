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
        .expect("Failed to parse baremetal_measurements.json at compile time")
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
                            Slot4: 1c96ef5ecac61c0c2cb26d7b4ae4cf43ba5bed073c6b29fe4f6ad008aa4a2c32,
                            Slot5: cf4dc5c88dd9735666596c7bd8bd51bf961ba2ea219b9e52cf3633bb8b136597,
                            Slot6: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot7: b5710bf57d25623e4019027da116821fa99f5c81e9e38b87671cc574f9281439,
                            Slot8: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot9: 3ada7ec56e06f29f4ec5cce007b2b9aad7323dd57f3433fab1a68f8fe057d62c,
                            Slot10: b3fb39e58d186eb59921dcf8970cd940a5fab7269fa1578537a7481667861e2c,
                            Slot11: c7e18cd7b879dcc5c5bd20be5c86e642b071cb06d855ea86e76cc4136a63cd9e,
                            Slot12: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot13: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot14: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot15: 5f18b36ff47141fe85695decb3b5c385bb8a65d372aef607e5605cd9f912168c,
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

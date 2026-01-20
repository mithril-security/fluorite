mod collateral;

use crate::SvsmVtpmAttestationDocument;
use anyhow::{bail, Context, Ok};
use attestation::VerifyAttestationDocument;
use collateral::validate_cert_metadata;
use rustls_pki_types::UnixTime;
use sev::{
    certs::snp::{self, ca, Certificate, Verifiable},
    CpuFamily, CpuModel, Generation,
};
use sha2::{Digest, Sha512};

use tpm_quote::{
    common::SanitizedPcrData,
    verify::{AttestationKey, EccAttestationKey},
};

impl VerifyAttestationDocument for SvsmVtpmAttestationDocument {
    fn verify(&self, _now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        // TODO: Use arg now to check for expiration
        // Reference: https://www.amd.com/content/dam/amd/en/documents/developer/58217-epyc-9004-ug-platform-attestation-using-virtee-snp.pdf

        let nonce = [0u8; 64];
        let nonce_and_manifest = [&nonce[..], &self.ak_pub_key[..]].concat();
        let hash = Sha512::digest(&nonce_and_manifest);

        // Verifying AK pub key against Attestation report
        // let hash_ak_pkey = sha512(&ak_pub_key);
        if *self.attestation_report.report_data != *hash {
            bail!("Report data doesn't match the hash of the AK public key. \nreport_data {} \nhash_ak_pkey {}", hex::encode(self.attestation_report.report_data), hex::encode(hash))
        }

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
                            Slot0: 3b7a62f6f325cacae0f079c6b5e8e55b99ba314611ff00f5c4696c1c409e8632,
                            Slot1: a47c0c14e211a32310e7cf0d94503a694c1b96a9a64e90ba447a638df80c834e,
                            Slot2: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot3: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot4: 58b43b32ed041911ae400f99faa90fa8f46de8d6be2c42180c5190c0729c1e46,
                            Slot5: 4b30ddda9060e21523d5f61debd6f1741349dcbada5d1ac2007dcfc8a618771e,
                            Slot6: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot7: 127c18eba2300e30767fafe71f4e5975776f665d22c7ca9017c7c24846b96fa1,
                            Slot8: 3e0639d9a3fd887b534a0423941805632c173ea2e7fa7797a4064cf71ddc1e22,
                            Slot9: be8a49cca5cc581623f7b2259376a22b1e3c3e9a13ce64fea1e3e81fe342a357,
                            Slot10: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot11: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot12: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot13: 0000000000000000000000000000000000000000000000000000000000000000,
                            Slot14: 306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf,
                            Slot15: 0000000000000000000000000000000000000000000000000000000000000000,
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

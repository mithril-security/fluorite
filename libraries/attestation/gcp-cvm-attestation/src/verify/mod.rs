mod collateral;
use crate::CvmAttestationDocument;
use attestation::VerifyAttestationDocument;
use collateral::validate_ak_chain;
use fn_error_context::context;
use rustls_pki_types::UnixTime;
use tpm_quote::{
    common::SanitizedPcrData,
    verify::{AttestationKey, EccAttestationKey},
};

impl VerifyAttestationDocument for CvmAttestationDocument {
    #[context("CvmAttestationDocument::verify failed")]
    fn verify(&self, now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        let CvmAttestationDocument {
            quote,
            ak_cert_chain,
        } = self;

        let leaf_cert = validate_ak_chain(&ak_cert_chain[..], now)?;
        let ak = EccAttestationKey::try_from_der(leaf_cert)?;
        let pcr_data = ak.verify_quote(&quote)?;
        Ok(pcr_data)
    }
}

#[test]
fn test_gcp_cvm_attestation_document_verify() -> anyhow::Result<()> {
    use std::fs;
    let attestation_doc: CvmAttestationDocument =
        serde_json::from_slice(&fs::read("test_data/gcp_cvm_attestation_document.json")?)?;
    let pcr_data = attestation_doc.verify(UnixTime::now())?;
    insta::assert_debug_snapshot!(pcr_data,@r###"
    SanitizedPcrData(
        PcrData {
            data: [
                (
                    Sha256,
                    PcrBank {
                        bank: {
                            Slot0: a0b5ff3383a1116bd7dc6df177c0c2d433b9ee1813ea958fa5d166a202cb2a85,
                            Slot1: a45ce488a2b75909e6560f1a76da70563c0c87cf1bd99d2b16140b065cae1831,
                            Slot2: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot3: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot4: 824db11500993f875b709344cb2ad8421b7dc846b272f5316759804c675df82c,
                            Slot5: 8d2bee560a81081734f05ada485323b78ac371404285ea7d5ca0887c2b2a9eeb,
                            Slot6: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot7: 086e56e421422dbccc7a9633f161d38398174262aa69ed2a5bd5bd19a71c544b,
                        },
                    },
                ),
            ],
        },
    )
    "###);
    Ok(())
}

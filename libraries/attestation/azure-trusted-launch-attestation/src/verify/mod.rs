mod collateral;

use crate::TrustedLaunchVmAttestationDocument;
use anyhow::bail;
use attestation::VerifyAttestationDocument;
use collateral::validate_ak_cert_chain;
use fn_error_context::context;
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::Sha256;
use tpm_quote::{common::SanitizedPcrData, verify::AttestationKey};
use tpm_structs::{TpmLimits, TpmiAlgHash, TpmtSignature};
use webpki::EndEntityCert;

use anyhow::anyhow;

impl VerifyAttestationDocument for TrustedLaunchVmAttestationDocument {
    #[context("TrustedLaunchVmAttestationDocument::verify failed")]
    fn verify(&self, now: UnixTime) -> anyhow::Result<SanitizedPcrData> {
        let TrustedLaunchVmAttestationDocument {
            quote,
            ak_cert_chain,
        } = self;

        let leaf_cert = validate_ak_cert_chain(&ak_cert_chain[..], now)?;
        let ak = TrustedLaunchAttestationKey::from_cert(&leaf_cert)?;
        let pcr_data = ak.verify_quote(quote)?;

        Ok(pcr_data)
    }
}

struct TrustedLaunchAttestationKey(CertificateDer<'static>);

impl TrustedLaunchAttestationKey {
    pub fn from_cert(cert: &CertificateDer) -> anyhow::Result<TrustedLaunchAttestationKey> {
        Ok(TrustedLaunchAttestationKey(cert.clone().into_owned()))
    }
}

impl AttestationKey for TrustedLaunchAttestationKey {
    type Digest = Sha256;

    #[context("TrustedLaunchAttestationKey::verify_signature failed")]
    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        // Parse the signature
        let ([], tpmt_signature) = TpmtSignature::unmarshal(signature, &TpmLimits::default())
            .map_err(|_| anyhow!("Bad signature. Not a TPMT_SIGNATURE"))?
        else {
            bail!("Bad signature.")
        };

        let TpmtSignature::Rsassa(rsa_signature) = *tpmt_signature else {
            bail!(
                "Quote signature uses an unexpected scheme: expected RsaSsa, got {:?}",
                tpmt_signature.kind()
            );
        };

        if rsa_signature.hash != TpmiAlgHash::Sha256 {
            bail!(
                "Quote signature uses unexpected hashing algorithm: expected Sha256, got {:?}",
                rsa_signature.hash
            );
        }

        let ee_cert = EndEntityCert::try_from(&self.0)?;
        ee_cert
            .verify_signature(
                webpki::ring::RSA_PKCS1_2048_8192_SHA256,
                message,
                &rsa_signature.sig.buffer[..],
            )
            .map_err(|_| anyhow!("Bad RSA signature"))?;

        Ok(())
    }
}

#[test]
fn test_azure_trusted_launch_vm_attestation_document_verify_ok() -> anyhow::Result<()> {
    use std::fs;
    let doc: TrustedLaunchVmAttestationDocument = serde_json::from_slice(&fs::read(
        "test_data/azure_trusted_launch_vm_attestation_document.json",
    )?)?;

    let pcr_data = doc.verify(UnixTime::now())?;
    insta::assert_debug_snapshot!(pcr_data,@r"
    SanitizedPcrData(
        PcrData {
            data: [
                (
                    Sha256,
                    PcrBank {
                        bank: {
                            Slot0: e15c44796beabf46abcec7c57e590942041e47497e4ec27571c8b7664f48dced,
                            Slot1: d8e9d533748ae76840ef395cc63b6966c72d2eb4ef98a8f78c655e891fb27b45,
                            Slot2: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot3: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                            Slot4: ee09c36775e93717dc31e4b4ae3e365de3a2b942d0209201ebae0881f586413a,
                            Slot5: 5a3e9b7fc4682b84a0104857d6d3a9b547bb27cebd434e11aa899c71597e2ad7,
                            Slot6: 9fb2ec143ad007181acd34da02999d5b62b4e04ef1da7bc5b3a73ac5508e33e9,
                            Slot7: bec9ae9f7ba62edc1e70e77adec7544a01289e77343f213ff44d46025d372887,
                            Slot8: e32ad38d47b3363f8e4205e97c6dfe1833639120625f46ff6e4dff5249ec5c52,
                            Slot9: 381ca84a830201aad89447c1ae40c1bb33973ea2e09333e2302afeb861153104,
                            Slot10: f3439b65bdf1d4a03e552f02489eaa1d0fe48380cdaa4def7accce07fdfdf74b,
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
    ");
    Ok(())
}

#[test]
fn test_azure_trusted_launch_vm_attestation_document_verify_expired_cert() -> anyhow::Result<()> {
    use std::fs;
    let doc: TrustedLaunchVmAttestationDocument = serde_json::from_slice(&fs::read(
        "test_data/azure_trusted_launch_vm_attestation_document_expired.json",
    )?)?;

    assert_eq!(
        "Invalid Azure AK certificate chain",
        doc.verify(UnixTime::now())
            .unwrap_err()
            .chain()
            .next()
            .unwrap()
            .source()
            .unwrap()
            .to_string()
    );
    Ok(())
}

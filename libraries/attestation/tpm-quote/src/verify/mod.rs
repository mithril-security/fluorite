//! Verify quotes with Attestation Key.

use std::collections::BTreeMap;

use crate::common::pcr::selection::PcrSelection;
use crate::common::{PcrBank, PcrData, Quote, SanitizedPcrData};
use anyhow::{anyhow, bail, Context as _};
use digest::Output;
use fn_error_context::context;
use p256::NistP256;
use pkcs1::{RsaPublicKey, UintRef};
use rustls_pki_types::CertificateDer;
use sha2::Sha256;

use spki::der::Encode;
use spki::DecodePublicKey;
use tpm_structs::{
    TpmLimits, TpmiAlgHash, TpmiEccCurve, TpmsAttest, TpmsSchemeHash, TpmtEccSchemeWCV,
    TpmtKdfSchemeWCV, TpmtPublicMemberTyp, TpmtSignature, TpmtSymDefObjectWCV,
};
use webpki::EndEntityCert;

use p256::ecdsa::signature::Verifier;

/// Trait representing an Attestation Key, providing a method to verify TPM quote.
/// This trait is intended to be implemented on different attestation key algorithm, such as ECC and RSA.
#[doc(notable_trait)]
pub trait AttestationKey {
    /// The hash function of the signing key
    type Digest: digest::Digest;

    /// Verifies the signature of the message.
    ///
    /// # Parameters
    /// - `message`: The message that was signed with Attestation Key.
    /// - `signature`: The signature to be verified.
    ///
    /// # Errors
    /// Returns an error if the signature is invalid.
    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()>;

    /// Verifies a quote and returns the validated PCR data.
    ///
    /// # Parameters
    /// - `quote`: The quote containing the message, signature, and untrusted PCR data.
    ///
    /// # Returns
    /// Returns the validated PCR data if verification is successful.
    ///
    /// # Errors
    /// Returns an error if the quote's signature is invalid, the message is malformed,
    /// or if the PCR data is bad.
    fn verify_quote(&self, quote: &Quote) -> anyhow::Result<SanitizedPcrData> {
        self.verify_signature(&quote.message, &quote.signature)?;
        // Parse the message (the quote)

        // SECURITY:
        // The Trusted Platform Module Library Part 1: Architecture [1] states in 9.5.3.2:
        // an entity checking an attestation made by an AK must verify that
        // the message signed begins with TPM_GENERATED_VALUE in order
        // to verify the message is indeed a TPM-generated quote.
        //
        // We are not checking it here because this check is already done while unmarshaling with TpmsAttest::unmarshal
        // The unmarshalling will fail with an error on struct that does not have the right magic
        // bytes.
        let Ok(([], tpms_attest)) =
            TpmsAttest::unmarshal(&quote.message[..], &TpmLimits::default())
        else {
            bail!("Bad message. Not a TPMS_ATTEST")
        };

        let tpm_structs::TpmsAttestMemberTyp::AttestQuote(quote_info) = tpms_attest.typ else {
            bail!("TPMS_ATTEST type is not a quote");
        };

        let pcr_selection_list = quote_info
            .pcr_select
            .pcr_selections
            .into_iter()
            .map(|x| {
                PcrSelection::try_from(x).map_err(|_| anyhow!("Failed to parse TPMS_PCR_SELECTION"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let pcr_data = extract_selection_from_pcr_data(&pcr_selection_list, &quote.pcr_data)?;
        if &pcr_data.pcr_digest::<Self::Digest>()[..] != &quote_info.pcr_digest.buffer[..] {
            bail!("Bad composite digest value of the PCR values");
        }
        Ok(pcr_data)
    }
}

/// An ECC attestation key (NIST P-256).
pub struct EccAttestationKey(ecdsa::VerifyingKey<NistP256>);

impl EccAttestationKey {
    /// Creates an `RsaAttestationKey` from a TPMT_PUBLIC structure.
    ///
    /// # Parameters
    /// - `public_key`: A marshalled TPMT_PUBLIC
    ///
    /// # Returns
    /// Returns an `EccAttestationKey`
    ///
    /// # Errors
    /// Returns an error if the public key cannot be parsed or if an unexpected public key format is encountered.
    #[context("EccAttestationKey::try_from_tpmt_public failed")]
    pub fn try_from_tpmt_public(tpmt_public: &[u8]) -> anyhow::Result<Self> {
        let unmarshalled_tpmt_public =
            tpm_structs::TpmtPublic::unmarshal(&tpmt_public, &TpmLimits::default())
                .map_err(|_| anyhow!("Failed to unmarshal TPMT_PUBLIC"))?
                .1;

        let TpmtPublicMemberTyp::Ecc { parameters, unique } = unmarshalled_tpmt_public.typ else {
            bail!("Not a ECC public key")
        };

        if parameters.symmetric != TpmtSymDefObjectWCV::Null {
            bail!("EccAttestationKey symmetric field is not TpmtSymDefObjectWCV::Null");
        }

        if parameters.curve_id != TpmiEccCurve::NistP256 {
            bail!("EccAttestationKey is not an TpmiEccCurve::NistP256");
        }

        if parameters.scheme
            != TpmtEccSchemeWCV::Ecdsa(TpmsSchemeHash {
                hash_alg: TpmiAlgHash::Sha256,
            })
        {
            bail!("EccAttestationKey scheme is not Ecdsa(Sha256)");
        }

        if parameters.kdf != TpmtKdfSchemeWCV::Null {
            bail!("EccAttestationKey kdf is not TpmtKdfSchemeWCV::Null");
        }

        let (x, y) = (&unique.x.buffer[..], &unique.y.buffer[..]);
        let point = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);

        let pub_key: ecdsa::VerifyingKey<NistP256> =
            p256::ecdsa::VerifyingKey::from_encoded_point(&point)?;

        Ok(EccAttestationKey(pub_key))
    }

    /// Creates an `EccAttestationKey` from a PEM-encoded ECC Public Key.
    ///
    /// # Parameters
    /// - `pem`: The PEM-encoded Public Key.
    ///
    /// # Returns
    /// Returns an `EccAttestationKey`
    ///
    /// # Errors
    /// Returns an error if the Public Key cannot be parsed or if an unexpected public key format is encountered.
    #[context("EccAttestationKey::try_from_pem failed")]
    pub fn try_from_pem(pem: &str) -> anyhow::Result<Self> {
        let pub_key: ecdsa::VerifyingKey<NistP256> =
            p256::ecdsa::VerifyingKey::from_public_key_pem(pem)?;
        Ok(EccAttestationKey(pub_key))
    }

    /// Creates an `EccAttestationKey` from a DER-encoded certificate.
    ///
    /// # Parameters
    /// - `der`: The DER-encoded certificate.
    ///
    /// # Returns
    /// Returns an `EccAttestationKey` from the certificate subject public key information.
    ///
    /// # Errors
    /// Returns an error if the certificate cannot be parsed or if an unexpected public key format is encountered.
    #[context("EccAttestationKey::try_from_der failed")]
    pub fn try_from_der(der: CertificateDer<'_>) -> anyhow::Result<EccAttestationKey> {
        let ee_cert = EndEntityCert::try_from(&der)?;
        let spki = &ee_cert.subject_public_key_info()[..];
        let pub_key: ecdsa::VerifyingKey<NistP256> =
            p256::ecdsa::VerifyingKey::from_public_key_der(spki)?;
        Ok(EccAttestationKey(pub_key))
    }
}
/// An RSA attestation key.
pub struct RsaAttestationKey(ring::signature::UnparsedPublicKey<Vec<u8>>);

impl RsaAttestationKey {
    /// Creates an `RsaAttestationKey` from a PEM-encoded RSA Public Key.
    ///
    /// # Parameters
    /// - `pem`: The PEM-encoded Public Key.
    ///
    /// # Returns
    /// Returns an `RsaAttestationKey`
    ///
    /// # Errors
    /// Returns an error if the Public Key cannot be parsed or if an unexpected public key format is encountered.
    #[context("RsaAttestationKey::try_from_pem failed")]
    pub fn try_from_pem(pem: &str) -> anyhow::Result<Self> {
        use spki::der::DecodePem as _;

        let my_spki = spki::SubjectPublicKeyInfoOwned::from_pem(pem)?;
        let _ = my_spki
            .algorithm
            .assert_algorithm_oid(const_oid::db::rfc5912::RSA_ENCRYPTION)?;

        let pubkey = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            my_spki.subject_public_key.as_bytes().unwrap().to_vec(),
        );
        Ok(RsaAttestationKey(pubkey))
    }

    /// Creates an `RsaAttestationKey` from a TPMT_PUBLIC structure.
    ///
    /// # Parameters
    /// - `public_key`: A marshalled TPMT_PUBLIC
    ///
    /// # Returns
    /// Returns an `RsaAttestationKey`
    ///
    /// # Errors
    /// Returns an error if the public key cannot be parsed or if an unexpected public key format is encountered.
    #[context("RsaAttestationKey::try_from_tpmt_public failed")]
    pub fn try_from_tpmt_public(tpmt_public: &[u8]) -> anyhow::Result<Self> {
        let unmarshalled_tpmt_public =
            tpm_structs::TpmtPublic::unmarshal(&tpmt_public, &TpmLimits::default())
                .map_err(|_| anyhow!("Failed to unmarshal TPMT_PUBLIC"))?
                .1;

        let TpmtPublicMemberTyp::Rsa { parameters, unique } = unmarshalled_tpmt_public.typ else {
            bail!("Not a RSA public key")
        };

        // Handle the Empty exponent (internal value is 0), which is treated by TPMs
        // as a shorthand for the default value (2^16 + 1).
        let e = match parameters.exponent {
            0 => (1 << 16) + 1,
            _ => parameters.exponent,
        }
        .to_be_bytes();

        let n = unique.buffer;

        let pkcs1_pub_key = RsaPublicKey {
            modulus: UintRef::new(&n[..]).map_err(|_| anyhow!("Error parsing RSA modulus"))?,
            public_exponent: UintRef::new(&e)
                .map_err(|_| anyhow!("Error parsing RSA public exponent"))?,
        };

        Ok(RsaAttestationKey(ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            pkcs1_pub_key.to_der()?,
        )))
    }
}

impl AttestationKey for EccAttestationKey {
    type Digest = Sha256;

    #[context("EccAttestationKey::verify_signature failed")]
    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        let ([], tpmt_signature) = TpmtSignature::unmarshal(&signature[..], &TpmLimits::default())
            .map_err(|_| anyhow!("Bad signature. Not a TPMT_SIGNATURE"))?
        else {
            bail!("Bad signature.")
        };
        let TpmtSignature::Ecdsa(ecc_signature) = *tpmt_signature else {
            bail!(
                "Quote signature uses an unexpected scheme: expected Ecdsa, got {:?}",
                tpmt_signature.kind()
            );
        };

        if ecc_signature.hash != TpmiAlgHash::Sha256 {
            bail!(
                "Quote signature uses unexpected hashing algorithm: expected Sha256, got {:?}",
                ecc_signature.hash
            );
        }
        const P256_SCALAR_SIZE: usize = 32;
        let r = &ecc_signature.signature_r.buffer[..];
        let r: &[u8; P256_SCALAR_SIZE] = r
            .try_into()
            .map_err(|_| anyhow!("Wrong size for scalar r in NIST P-256 signature"))?;

        let s = &ecc_signature.signature_s.buffer[..];
        let s: &[u8; P256_SCALAR_SIZE] = s
            .try_into()
            .map_err(|_| anyhow!("Wrong size for scalar s in NIST P-256 signature"))?;

        let sig = p256::ecdsa::Signature::from_scalars(*r, *s)?;
        self.0.verify(&message, &sig).context("Bad signature")?;
        Ok(())
    }
}

impl AttestationKey for RsaAttestationKey {
    type Digest = Sha256;

    #[context("RsaAttestationKey::verify_signature failed")]
    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        // Parse the signature
        let ([], tpmt_signature) = TpmtSignature::unmarshal(&signature[..], &TpmLimits::default())
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

        self.0
            .verify(&message[..], &rsa_signature.sig.buffer[..])
            .map_err(|_| anyhow!("Bad RSA signature"))?;

        Ok(())
    }
}

/// Extracts the PCR data corresponding to the given selection from the provided PCR data.
///
/// The returned PCR data contains exactly the digests that are selected.
/// The input `pcr_data` is considered untrusted, and the returned PCR data is sanitized.
///
/// # Parameters
/// - `pcr_selections`: A list of PCR selections.
/// - `pcr_data`: The untrusted PCR data from which to extract the selected values.
///
/// # Returns
/// Returns sanitized PCR data for the selected PCRs
///
/// # Errors
/// Returns an error if the PCR data cannot be built. This may happen if the PCR data lack the selected PCR slot.
#[context("extract_selection_from_pcr_data failed")]
fn extract_selection_from_pcr_data(
    pcr_selections: &[PcrSelection],
    pcr_data: &PcrData,
) -> anyhow::Result<SanitizedPcrData> {
    let mut build_pcr_data = PcrData { data: vec![] };
    for pcr_selection in pcr_selections {
        let hashing_alg = pcr_selection.hashing_algorithm();
        let Some(pcr_bank) = pcr_data.pcr_bank(hashing_alg) else {
            bail!("Missing bank in provided PcrData");
        };
        let mut build_pcr_bank = PcrBank {
            bank: BTreeMap::new(),
        };
        for slot in pcr_selection.selected() {
            let Some(digest) = pcr_bank.bank.get(&slot) else {
                bail!("Missing digest in provided {:?} PCR bank", hashing_alg);
            };
            if digest.0.len() != hashing_alg.digest_size() as usize {
                bail!("Wrong digest size for {:?} PCR bank", hashing_alg);
            }
            build_pcr_bank.bank.insert(slot, digest.clone());
        }
        build_pcr_data.data.push((hashing_alg, build_pcr_bank));
    }
    Ok(SanitizedPcrData(build_pcr_data))
}

impl SanitizedPcrData {
    /// Calculates the digest of the PCR data across all banks.
    ///
    /// # Returns
    /// Returns the calculated digest.
    fn pcr_digest<T: digest::Digest>(&self) -> Output<T> {
        let mut hasher = T::new();

        for (_, bank) in self.data.iter() {
            for (_, digest) in bank.bank.iter() {
                hasher.update(&digest.0);
            }
        }

        hasher.finalize()
    }
}

#[cfg(test)]
mod test {

    use std::fs;

    use crate::common::Quote;
    use crate::verify::AttestationKey;
    use crate::verify::EccAttestationKey;
    use crate::verify::RsaAttestationKey;

    #[test]
    fn test_verify_quote_rsa_with_shielded_vm_data() -> anyhow::Result<()> {
        let quote: Quote = serde_json::from_slice(&fs::read("test_data/gcp_quote.json")?)?;
        let pem = fs::read_to_string("test_data/shielded_vm_pub_key.pem")?;
        let ak = RsaAttestationKey::try_from_pem(&pem)?;
        insta::assert_debug_snapshot!(ak.verify_quote(&quote)?,@r###"
        SanitizedPcrData(
            PcrData {
                data: [
                    (
                        Sha256,
                        PcrBank {
                            bank: {
                                Slot0: d0c70a9310cd0b55767084333022ce53f42befbb69c059ee6c0a32766f160783,
                                Slot1: 733d777d87913a3efbfd3c85a68c79fd7d77133bc7348763d57407eb2416f345,
                                Slot2: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                                Slot3: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                                Slot4: e400522fa78f9e1206086aa4c2741027dee88e9b7e10c5245c7e9ab2a4c1c84e,
                                Slot5: d29d6d662c0fb3aa8560928eab4ee51979cf9e6dc8508eead32d36df30ae9dae,
                                Slot6: 3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969,
                                Slot7: 80cf53255c50c0fee61a4dd51bca90aaa9be2ce41dfa3dc11c9a5e365934ee8d,
                            },
                        },
                    ),
                ],
            },
        )
        "###);
        Ok(())
    }

    #[test]
    fn test_verify_parse_tpmtp_public_ecc() -> anyhow::Result<()> {
        let tmptpublic: &[u8] = &[
            0, 35, 0, 11, 0, 4, 4, 114, 0, 0, 0, 16, 0, 24, 0, 11, 0, 3, 0, 16, 0, 32, 163, 235,
            247, 51, 17, 35, 207, 169, 85, 22, 141, 130, 120, 179, 80, 57, 44, 127, 225, 141, 157,
            77, 227, 20, 241, 20, 63, 30, 24, 60, 240, 163, 0, 32, 44, 139, 2, 70, 135, 138, 116,
            97, 5, 121, 131, 139, 236, 9, 21, 218, 101, 54, 220, 87, 155, 100, 64, 195, 125, 181,
            167, 17, 21, 206, 156, 224,
        ];
        let _ = EccAttestationKey::try_from_tpmt_public(tmptpublic)?;

        Ok(())
    }
}
